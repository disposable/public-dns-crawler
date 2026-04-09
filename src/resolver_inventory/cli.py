"""Command-line interface for resolver-inventory."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from resolver_inventory.util.logging import configure_logging, get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from resolver_inventory.models import ValidationResult
    from resolver_inventory.settings import Settings
    from resolver_inventory.validate import ValidationProgress

DEFAULT_SHARD_COUNT = 10


def _github_output(name: str, value: str) -> None:
    """Write a key-value pair to GITHUB_OUTPUT if running in GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        output_file = os.environ.get("GITHUB_OUTPUT")
        if output_file:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{name}={value}\n")


def _github_group(title: str) -> None:
    """Start a collapsible group in GitHub Actions logs."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::group::{title}", flush=True)


def _github_endgroup() -> None:
    """End a collapsible group in GitHub Actions logs."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::endgroup::", flush=True)


def _github_notice(message: str) -> None:
    """Emit a notice annotation in GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::notice::{message}", flush=True)


def _make_validation_progress_logger(
    label: str,
    *,
    every: int = 250,
    interval_s: float = 30.0,
):
    """Return a callback that emits periodic validation progress."""
    last_emit = 0.0

    def report(progress: ValidationProgress) -> None:
        nonlocal last_emit
        now = time.monotonic()
        if progress.completed != progress.total:
            if progress.completed % every != 0 and (now - last_emit) < interval_s:
                return
        last_emit = now
        if progress.result is not None:
            message = (
                f"{label} progress: {progress.completed}/{progress.total} "
                f"({progress.result.status}) {progress.candidate}"
            )
        else:
            pct = (
                int(progress.probes_done * 100 / progress.probes_total)
                if progress.probes_total
                else 0
            )
            message = (
                f"{label} progress: probes {progress.probes_done}/{progress.probes_total} ({pct}%)"
            )
        logger.info(message)
        _github_notice(message)

    return report


def _format_elapsed(seconds: float) -> str:
    whole = max(0, int(seconds))
    minutes, sec = divmod(whole, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes}m{sec}s"
    if minutes:
        return f"{minutes}m{sec}s"
    return f"{sec}s"


class _ValidateProgressReporter:
    def __init__(self, *, total: int, input_label: str, every: int = 100) -> None:
        self.total = total
        self.input_label = input_label
        self.every = max(1, every)
        self._start = time.monotonic()
        self._last_emitted = 0
        self._accepted = 0
        self._candidate = 0
        self._rejected = 0
        self._lock = threading.Lock()

    def emit_start(self) -> None:
        print(f"[validate] start input={self.input_label} total={self.total}", flush=True)

    def callback(self, progress: ValidationProgress) -> None:
        with self._lock:
            if progress.result is not None:
                if progress.result.status == "accepted":
                    self._accepted += 1
                elif progress.result.status == "candidate":
                    self._candidate += 1
                else:
                    self._rejected += 1

            is_heartbeat = progress.result is None
            should_emit = (
                is_heartbeat
                or progress.completed == self.total
                or (progress.completed - self._last_emitted) >= self.every
            )
            if not should_emit:
                return
            self._emit_progress(progress.completed, progress.probes_done, progress.probes_total)
            if not is_heartbeat:
                self._last_emitted = progress.completed

    def emit_done(self) -> None:
        with self._lock:
            if self.total == 0 or self._last_emitted != self.total:
                self._emit_progress(self.total)
                self._last_emitted = self.total
            elapsed = _format_elapsed(time.monotonic() - self._start)
            print(
                f"[validate] done processed={self.total} total={self.total} "
                f"percent=100 elapsed={elapsed} accepted={self._accepted} "
                f"candidate={self._candidate} rejected={self._rejected}",
                flush=True,
            )

    def _emit_progress(self, done: int, probes_done: int = 0, probes_total: int = 0) -> None:
        percent = 100 if self.total == 0 else int((done * 100) / self.total)
        elapsed = _format_elapsed(time.monotonic() - self._start)
        probe_info = f" probes={probes_done}/{probes_total}" if probes_total > 0 else ""
        print(
            f"[validate] progress done={done} total={self.total} "
            f"percent={percent} elapsed={elapsed}{probe_info} accepted={self._accepted} "
            f"candidate={self._candidate} rejected={self._rejected}",
            flush=True,
        )


def _apply_probe_corpus_override(args: argparse.Namespace, settings: Settings) -> None:
    probe_corpus = getattr(args, "probe_corpus", None)
    if not probe_corpus:
        return
    settings.validation.corpus.path = probe_corpus
    settings.validation.corpus.mode = "external"


def _apply_validation_parallelism_override(args: argparse.Namespace, settings: Settings) -> None:
    parallelism = getattr(args, "validation_parallelism", None)
    if parallelism is None:
        return
    settings.validation.parallelism = parallelism


def _apply_dns_backend_overrides(args: argparse.Namespace, settings: Settings) -> None:
    backend = getattr(args, "dns_backend", None)
    if backend is not None:
        settings.validation.dns_backend.kind = backend

    massdns_bin = getattr(args, "massdns_bin", None)
    if massdns_bin is not None:
        settings.validation.dns_backend.massdns_bin = massdns_bin

    massdns_hashmap_size = getattr(args, "massdns_hashmap_size", None)
    if massdns_hashmap_size is not None:
        settings.validation.dns_backend.hashmap_size = massdns_hashmap_size


def _candidate_sort_key(candidate) -> tuple[str, str, str, int, str]:
    return (
        candidate.transport,
        candidate.endpoint_url or "",
        candidate.host,
        candidate.port,
        candidate.path or "",
    )


def _validation_candidate_sort_key(candidate, settings: Settings) -> tuple[int, str, str, int, str]:
    if (
        settings.validation.dns_backend.kind == "massdns"
        and candidate.transport == "dns-udp"
        and candidate.port == 53
    ):
        priority = 0
    elif candidate.transport in {"dns-udp", "dns-tcp"}:
        priority = 1
    else:
        priority = 2
    transport, endpoint_url, host, port, path = _candidate_sort_key(candidate)
    return (priority, transport, endpoint_url, host, port, path)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def cmd_discover(args: argparse.Namespace) -> int:
    from resolver_inventory.export.json import export_filtered_json
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.serialization import candidate_to_dict, write_json
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates_with_filtered

    settings = load_settings(args.config)
    discovery = discover_candidates_with_filtered(settings)
    filtered_candidates = list(discovery.filtered)
    dns_c = normalize_dns_candidates(discovery.candidates, filtered=filtered_candidates)
    doh_c = normalize_doh_candidates(discovery.candidates, filtered=filtered_candidates)
    all_c = dns_c + doh_c
    logger.info("Discovered %d candidates (%d DNS, %d DoH)", len(all_c), len(dns_c), len(doh_c))
    _github_output("candidates_total", str(len(all_c)))
    _github_output("filtered_total", str(len(filtered_candidates)))

    if args.output:
        write_json(args.output, [candidate_to_dict(candidate) for candidate in all_c])
        logger.info("Wrote candidates to %s", args.output)
        _github_output("output_path", str(Path(args.output).resolve()))
    if args.filtered_output:
        export_filtered_json(filtered_candidates, path=args.filtered_output)
        logger.info("Wrote filtered candidates to %s", args.filtered_output)
        _github_output("filtered_path", str(Path(args.filtered_output).resolve()))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    from resolver_inventory.export.json import (
        StreamingJsonArrayWriter,
        validation_result_to_dict_export,
    )
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.serialization import candidate_from_dict, load_json_list
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates
    from resolver_inventory.validate import validate_candidates_stream

    settings = load_settings(args.config)
    _apply_probe_corpus_override(args, settings)
    _apply_validation_parallelism_override(args, settings)
    _apply_dns_backend_overrides(args, settings)

    _github_group("Discovery")
    if args.input:
        candidates = [candidate_from_dict(record) for record in load_json_list(args.input)]
        candidates.sort(key=lambda candidate: _validation_candidate_sort_key(candidate, settings))
        logger.info("Loaded %d candidates from %s", len(candidates), args.input)
    else:
        raw_candidates = discover_candidates(settings)
        candidates = normalize_dns_candidates(raw_candidates) + normalize_doh_candidates(
            raw_candidates
        )
        candidates.sort(key=lambda candidate: _validation_candidate_sort_key(candidate, settings))
        logger.info("Discovered %d normalized candidates", len(candidates))
    _github_endgroup()

    _github_output("candidates_total", str(len(candidates)))

    _github_group("Validation")
    logger.info("Validating %d candidates…", len(candidates))
    progress = _ValidateProgressReporter(
        total=len(candidates),
        input_label=args.input or "discovered",
        every=args.progress_every,
    )
    progress.emit_start()
    out_path = args.output or "outputs/validated.json"
    split_json_max_bytes = getattr(args, "split_json_max_bytes", None)
    accepted = 0
    candidate_count = 0
    rejected = 0
    if split_json_max_bytes is not None and split_json_max_bytes < 3:
        raise ValueError("--split-json-max-bytes must be at least 3")
    writer = StreamingJsonArrayWriter(Path(out_path), max_file_bytes=split_json_max_bytes)

    def _handle_result(result: ValidationResult) -> None:
        nonlocal accepted, candidate_count, rejected
        if result.status == "accepted":
            accepted += 1
        elif result.status == "candidate":
            candidate_count += 1
        else:
            rejected += 1
        writer.write_record(
            validation_result_to_dict_export(
                result,
                rejected_failed_only=True,
            )
        )

    try:
        validate_candidates_stream(
            candidates,
            _handle_result,
            settings,
            progress_callback=progress.callback,
        )
    finally:
        writer.close()
    progress.emit_done()
    logger.info(
        "Results: %d accepted, %d candidate, %d rejected",
        accepted,
        candidate_count,
        rejected,
    )
    _github_endgroup()

    _github_output("results_accepted", str(accepted))
    _github_output("results_candidate", str(candidate_count))
    _github_output("results_rejected", str(rejected))
    _github_output("results_total", str(accepted + candidate_count + rejected))
    _github_notice(
        f"Validation complete: {accepted} accepted, "
        f"{candidate_count} candidate, {rejected} rejected"
    )

    _github_group("Export")
    logger.info("Wrote results to %s", out_path)
    _github_output("output_path", str(Path(out_path).resolve()))
    _github_endgroup()

    return 0


def cmd_split_candidates(args: argparse.Namespace) -> int:
    from resolver_inventory.serialization import (
        candidate_from_dict,
        candidate_to_dict,
        load_json_list,
        write_json,
    )

    candidates = [candidate_from_dict(record) for record in load_json_list(args.input)]
    candidates.sort(key=_candidate_sort_key)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    shard_count = args.shards
    total = len(candidates)
    base_size, remainder = divmod(total, shard_count)
    files: list[str] = []
    start = 0

    for shard_index in range(shard_count):
        shard_size = base_size + (1 if shard_index < remainder else 0)
        shard_candidates = candidates[start : start + shard_size]
        start += shard_size
        shard_path = output_dir / f"chunk-{shard_index:02d}.json"
        write_json(shard_path, [candidate_to_dict(candidate) for candidate in shard_candidates])
        files.append(shard_path.name)

    manifest = {
        "shards": shard_count,
        "total_candidates": total,
        "files": files,
    }
    manifest_path = output_dir.parent / "manifest.json"
    write_json(manifest_path, manifest)

    _github_output("shards", str(shard_count))
    _github_output("total_candidates", str(total))
    _github_output("manifest_path", str(manifest_path.resolve()))
    _github_output("chunks_dir", str(output_dir.resolve()))
    logger.info("Wrote %d shards to %s", shard_count, output_dir)
    return 0


def cmd_materialize_results(args: argparse.Namespace) -> int:
    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_filtered_json, export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.serialization import (
        filtered_candidate_from_dict,
        load_json_list,
        validation_result_from_dict,
    )
    from resolver_inventory.settings import load_settings

    settings = load_settings(args.config)
    split_json_max_bytes = getattr(args, "split_json_max_bytes", None)
    out_dir = Path(args.output or settings.export.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    filtered_candidates = [
        filtered_candidate_from_dict(record) for record in load_json_list(args.filtered_input)
    ]

    shard_paths = [Path(path) for path in sorted(glob.glob(args.inputs_glob))]
    if not shard_paths:
        logger.error("No validated shard files matched %s", args.inputs_glob)
        return 1
    results = []
    for shard_path in shard_paths:
        results.extend(validation_result_from_dict(record) for record in load_json_list(shard_path))

    accepted_status = sum(1 for result in results if result.status == "accepted")
    candidate_status = sum(1 for result in results if result.status == "candidate")
    rejected_status = sum(1 for result in results if result.status == "rejected")

    exported_files: list[str] = []
    filtered_path = out_dir / "filtered.json"
    export_filtered_json(
        filtered_candidates,
        path=filtered_path,
        max_file_bytes=split_json_max_bytes,
    )
    exported_files.append(str(filtered_path))

    formats = settings.export.formats
    if "json" in formats:
        accepted_path = out_dir / "accepted.json"
        candidate_path = out_dir / "candidate.json"
        rejected_path = out_dir / "rejected.json"
        export_json(
            results,
            statuses={"accepted"},
            path=accepted_path,
            max_file_bytes=split_json_max_bytes,
        )
        export_json(
            results,
            statuses={"candidate"},
            path=candidate_path,
            max_file_bytes=split_json_max_bytes,
        )
        export_json(
            results,
            statuses={"rejected"},
            rejected_failed_only=True,
            max_file_bytes=split_json_max_bytes,
            path=rejected_path,
        )
        exported_files.extend([str(accepted_path), str(candidate_path), str(rejected_path)])
    if "text" in formats:
        resolvers_path = out_dir / "resolvers.txt"
        doh_path = out_dir / "resolvers-doh.txt"
        export_text(results, path=resolvers_path)
        export_text(results, include_doh=True, path=doh_path)
        exported_files.extend([str(resolvers_path), str(doh_path)])
    if "dnsdist" in formats:
        dnsdist_path = out_dir / "dnsdist.conf"
        export_dnsdist(results, path=dnsdist_path)
        exported_files.append(str(dnsdist_path))
    if "unbound" in formats:
        unbound_path = out_dir / "unbound-forward.conf"
        export_unbound(results, path=unbound_path)
        exported_files.append(str(unbound_path))

    _github_output("results_accepted", str(accepted_status))
    _github_output("results_candidate", str(candidate_status))
    _github_output("results_rejected", str(rejected_status))
    _github_output("results_total", str(len(results)))
    _github_output("filtered_total", str(len(filtered_candidates)))
    _github_output("output_dir", str(out_dir.resolve()))
    _github_output("exported_files", ",".join(exported_files))
    _github_output("validated_shards", str(len(shard_paths)))
    logger.info("Materialized %d validation results into %s", len(results), out_dir)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    """Full pipeline: discover → validate → export all formats."""
    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_filtered_json, export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates_with_filtered
    from resolver_inventory.validate import validate_candidates

    settings = load_settings(args.config)
    split_json_max_bytes = getattr(args, "split_json_max_bytes", None)
    _apply_probe_corpus_override(args, settings)
    _apply_dns_backend_overrides(args, settings)
    out_dir = Path(args.output or settings.export.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filtered_candidates = []

    _github_group("Discovery")
    discovery = discover_candidates_with_filtered(settings)
    filtered_candidates.extend(discovery.filtered)
    candidates = normalize_dns_candidates(
        discovery.candidates,
        filtered=filtered_candidates,
    ) + normalize_doh_candidates(
        discovery.candidates,
        filtered=filtered_candidates,
    )
    logger.info("Discovered %d normalized candidates", len(candidates))
    _github_output("candidates_total", str(len(candidates)))
    _github_output("filtered_total", str(len(filtered_candidates)))
    _github_endgroup()

    _github_group("Validation")
    logger.info("Validating %d candidates…", len(candidates))
    results = validate_candidates(
        candidates,
        settings,
        progress_callback=_make_validation_progress_logger("refresh"),
    )
    accepted = [r for r in results if r.accepted]
    accepted_count = len(accepted)
    total_count = len(results)
    logger.info("%d/%d candidates accepted", accepted_count, total_count)

    accepted_status = sum(1 for r in results if r.status == "accepted")
    candidate_status = sum(1 for r in results if r.status == "candidate")
    rejected_status = sum(1 for r in results if r.status == "rejected")

    _github_output("results_accepted", str(accepted_status))
    _github_output("results_candidate", str(candidate_status))
    _github_output("results_rejected", str(rejected_status))
    _github_output("results_total", str(total_count))
    _github_notice(
        f"Pipeline complete: {accepted_status} accepted, "
        f"{candidate_status} candidate, {rejected_status} rejected"
    )
    _github_endgroup()

    _github_group("Export")
    formats = settings.export.formats
    exported_files: list[str] = []
    filtered_path = out_dir / "filtered.json"
    export_filtered_json(
        filtered_candidates,
        path=filtered_path,
        max_file_bytes=split_json_max_bytes,
    )
    exported_files.append(str(filtered_path))
    if "json" in formats:
        accepted_path = out_dir / "accepted.json"
        candidate_path = out_dir / "candidate.json"
        rejected_path = out_dir / "rejected.json"
        export_json(
            results,
            statuses={"accepted"},
            path=accepted_path,
            max_file_bytes=split_json_max_bytes,
        )
        export_json(
            results,
            statuses={"candidate"},
            path=candidate_path,
            max_file_bytes=split_json_max_bytes,
        )
        export_json(
            results,
            statuses={"rejected"},
            rejected_failed_only=True,
            max_file_bytes=split_json_max_bytes,
            path=rejected_path,
        )
        exported_files.extend([str(accepted_path), str(candidate_path), str(rejected_path)])
    if "text" in formats:
        p1 = out_dir / "resolvers.txt"
        p2 = out_dir / "resolvers-doh.txt"
        export_text(results, path=p1)
        export_text(results, include_doh=True, path=p2)
        exported_files.extend([str(p1), str(p2)])
    if "dnsdist" in formats:
        p = out_dir / "dnsdist.conf"
        export_dnsdist(results, path=p)
        exported_files.append(str(p))
    if "unbound" in formats:
        p = out_dir / "unbound-forward.conf"
        export_unbound(results, path=p)
        exported_files.append(str(p))

    _github_output("output_dir", str(out_dir.resolve()))
    _github_output("exported_files", ",".join(exported_files))
    _github_output("filtered_path", str(filtered_path.resolve()))
    _github_output("accepted_count", str(accepted_count))
    logger.info("Outputs written to %s", out_dir)
    _github_endgroup()

    return 0


def cmd_validate_probe_corpus(args: argparse.Namespace) -> int:
    from resolver_inventory.probe_corpus.schema import parse_probe_corpus
    from resolver_inventory.probe_corpus.validators import validate_probe_corpus
    from resolver_inventory.settings import load_settings

    try:
        settings = load_settings(args.config)
        parsed = parse_probe_corpus(
            json.loads(Path(args.input).read_text(encoding="utf-8")),
            required_schema_version=args.schema_version,
            strict=not args.no_strict,
        )
        counts = validate_probe_corpus(
            parsed,
            min_positive_exact=settings.probe_corpus.thresholds.min_positive_exact,
            min_positive_consensus=settings.probe_corpus.thresholds.min_positive_consensus,
            min_negative_generated=settings.probe_corpus.thresholds.min_negative_generated,
        )
    except Exception as exc:
        logger.error("Probe corpus validation failed: %s", exc)
        return 1

    print(
        f"schema_version={parsed.schema_version} corpus_version={parsed.corpus_version} "
        f"positive_exact={counts.get('positive_exact', 0)} "
        f"positive_consensus={counts.get('positive_consensus', 0)} "
        f"negative_generated={counts.get('negative_generated', 0)}"
    )
    return 0


def cmd_generate_probe_corpus(args: argparse.Namespace) -> int:
    from resolver_inventory.probe_corpus.exporters import write_probe_corpus_outputs
    from resolver_inventory.probe_corpus.generator import generate_probe_corpus
    from resolver_inventory.probe_corpus.sources import load_seed_snapshot
    from resolver_inventory.settings import load_settings

    settings = load_settings(args.config)
    seed_snapshot = load_seed_snapshot(args.seed_file or settings.probe_corpus.seed_path)
    result = generate_probe_corpus(settings.probe_corpus, seed_snapshot)
    output_dir = Path(args.output or "outputs/probe-corpus")
    write_probe_corpus_outputs(result, output_dir)
    print(f"candidates_seen={result.report.total_candidates}")
    print(f"accepted_probes={result.report.accepted_count}")
    for reason, count in sorted(result.report.rejected_by_reason.items()):
        print(f"rejected_{reason}={count}")
    for kind, count in sorted(result.report.accepted_counts.items()):
        print(f"{kind}={count}")
    print(f"output_dir={output_dir}")
    logger.info("Wrote probe corpus artifacts to %s", output_dir)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.serialization import load_json_list, validation_result_from_dict

    in_path = args.input or "outputs/validated.json"

    try:
        results = [validation_result_from_dict(item) for item in load_json_list(in_path)]
    except FileNotFoundError:
        logger.error("Input file not found: %s - run 'validate' first", in_path)
        return 1

    fmt = args.format
    out = args.output

    if fmt == "json":
        text = export_json(
            results,
            path=out,
            max_file_bytes=getattr(args, "split_json_max_bytes", None),
        )
    elif fmt == "text":
        text = export_text(results, path=out)
    elif fmt == "dnsdist":
        text = export_dnsdist(results, path=out)
    elif fmt == "unbound":
        text = export_unbound(results, path=out)
    else:
        logger.error("Unknown export format: %s", fmt)
        return 1

    if not out:
        print(text, end="")
    else:
        logger.info("Wrote %s export to %s", fmt, out)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", "-c", metavar="FILE", help="Path to TOML config file")

    parser = argparse.ArgumentParser(
        prog="resolver-inventory",
        description="Aggregate, validate, score, and export public DNS and DoH resolvers.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # discover
    p_discover = sub.add_parser(
        "discover", parents=[common], help="Gather raw candidates from all sources"
    )
    p_discover.add_argument("--output", "-o", metavar="FILE", help="Write candidates JSON here")
    p_discover.add_argument(
        "--filtered-output",
        metavar="FILE",
        help="Write filtered candidates JSON here",
    )

    # validate
    p_validate = sub.add_parser(
        "validate", parents=[common], help="Run probes and emit scored records"
    )
    p_validate.add_argument("--input", "-i", metavar="FILE", help="Pre-discovered candidates JSON")
    p_validate.add_argument("--output", "-o", metavar="FILE", help="Write validation results JSON")
    p_validate.add_argument(
        "--probe-corpus",
        metavar="FILE",
        help="Load validation probes from a local JSON corpus file",
    )
    p_validate.add_argument(
        "--validation-parallelism",
        type=int,
        metavar="INT",
        help="Override validation parallelism for this run",
    )
    p_validate.add_argument(
        "--dns-backend",
        choices=["python", "massdns"],
        metavar="KIND",
        help="Override plain DNS backend for this run",
    )
    p_validate.add_argument(
        "--massdns-bin",
        metavar="PATH",
        help="Path to MassDNS binary when --dns-backend=massdns",
    )
    p_validate.add_argument(
        "--massdns-hashmap-size",
        type=int,
        metavar="INT",
        help="Override MassDNS hashmap size when --dns-backend=massdns",
    )
    p_validate.add_argument(
        "--progress-every",
        type=int,
        default=100,
        metavar="INT",
        help="Emit a progress line every INT completed items (default: 100)",
    )
    p_validate.add_argument(
        "--split-json-max-bytes",
        type=int,
        metavar="INT",
        help="Split large JSON output files into .part-XXXX chunks of at most INT bytes",
    )

    # refresh
    p_refresh = sub.add_parser(
        "refresh", parents=[common], help="Full pipeline: discover → validate → export"
    )
    p_refresh.add_argument("--output", "-o", metavar="DIR", help="Output directory")
    p_refresh.add_argument(
        "--probe-corpus",
        metavar="FILE",
        help="Load validation probes from a local JSON corpus file",
    )
    p_refresh.add_argument(
        "--dns-backend",
        choices=["python", "massdns"],
        metavar="KIND",
        help="Override plain DNS backend for this run",
    )
    p_refresh.add_argument(
        "--massdns-bin",
        metavar="PATH",
        help="Path to MassDNS binary when --dns-backend=massdns",
    )
    p_refresh.add_argument(
        "--massdns-hashmap-size",
        type=int,
        metavar="INT",
        help="Override MassDNS hashmap size when --dns-backend=massdns",
    )
    p_refresh.add_argument(
        "--split-json-max-bytes",
        type=int,
        metavar="INT",
        help="Split large JSON output files into .part-XXXX chunks of at most INT bytes",
    )

    p_split = sub.add_parser(
        "split-candidates",
        parents=[common],
        help="Deterministically split discovered candidates into shard files",
    )
    p_split.add_argument("--input", required=True, metavar="FILE", help="Candidates JSON file")
    p_split.add_argument(
        "--output-dir",
        required=True,
        metavar="DIR",
        help="Directory for chunk-XX.json files",
    )
    p_split.add_argument(
        "--shards",
        type=int,
        default=DEFAULT_SHARD_COUNT,
        metavar="INT",
        help=f"Number of shards to write (default: {DEFAULT_SHARD_COUNT})",
    )

    p_materialize = sub.add_parser(
        "materialize-results",
        parents=[common],
        help="Merge validated shard results and regenerate final exports",
    )
    p_materialize.add_argument(
        "--inputs-glob",
        required=True,
        metavar="GLOB",
        help="Glob for validated shard JSON inputs",
    )
    p_materialize.add_argument(
        "--filtered-input",
        required=True,
        metavar="FILE",
        help="Filtered candidates JSON file from discovery stage",
    )
    p_materialize.add_argument("--output", "-o", metavar="DIR", help="Output directory")
    p_materialize.add_argument(
        "--split-json-max-bytes",
        type=int,
        metavar="INT",
        help="Split large JSON output files into .part-XXXX chunks of at most INT bytes",
    )

    # export
    p_export = sub.add_parser(
        "export", parents=[common], help="Render outputs from validated records"
    )
    p_export.add_argument(
        "format",
        choices=["json", "text", "dnsdist", "unbound"],
        help="Output format",
    )
    p_export.add_argument("--input", "-i", metavar="FILE", help="Validated results JSON")
    p_export.add_argument("--output", "-o", metavar="FILE", help="Write output here")
    p_export.add_argument(
        "--split-json-max-bytes",
        type=int,
        metavar="INT",
        help="Split large JSON output files into .part-XXXX chunks of at most INT bytes",
    )

    p_validate_corpus = sub.add_parser(
        "validate-probe-corpus",
        parents=[common],
        help="Validate a local probe corpus JSON file",
    )
    p_validate_corpus.add_argument(
        "--input",
        required=True,
        metavar="FILE",
        help="Corpus JSON file",
    )
    p_validate_corpus.add_argument(
        "--schema-version",
        type=int,
        default=1,
        help="Required schema version (default: 1)",
    )
    p_validate_corpus.add_argument(
        "--no-strict",
        action="store_true",
        help="Allow unsupported extra fields during schema validation",
    )

    p_generate_corpus = sub.add_parser(
        "generate-probe-corpus",
        parents=[common],
        help="Generate a reusable probe corpus from vendored infrastructure seeds",
    )
    p_generate_corpus.add_argument(
        "--seed-file",
        metavar="FILE",
        help="Optional seed snapshot JSON file",
    )
    p_generate_corpus.add_argument(
        "--output",
        "-o",
        metavar="DIR",
        help="Output directory for corpus artifacts",
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    handlers = {
        "discover": cmd_discover,
        "validate": cmd_validate,
        "refresh": cmd_refresh,
        "split-candidates": cmd_split_candidates,
        "materialize-results": cmd_materialize_results,
        "export": cmd_export,
        "generate-probe-corpus": cmd_generate_probe_corpus,
        "validate-probe-corpus": cmd_validate_probe_corpus,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
