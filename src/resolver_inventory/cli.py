"""Command-line interface for resolver-inventory."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from resolver_inventory.util.logging import configure_logging, get_logger

logger = get_logger(__name__)

if TYPE_CHECKING:
    from resolver_inventory.settings import Settings
    from resolver_inventory.validate import ValidationProgress


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
        message = (
            f"{label} progress: {progress.completed}/{progress.total} "
            f"({progress.result.status}) {progress.candidate}"
        )
        logger.info(message)
        _github_notice(message)

    return report


def _apply_probe_corpus_override(args: argparse.Namespace, settings: Settings) -> None:
    probe_corpus = getattr(args, "probe_corpus", None)
    if not probe_corpus:
        return
    settings.validation.corpus.path = probe_corpus
    settings.validation.corpus.mode = "external"


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def cmd_discover(args: argparse.Namespace) -> int:
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates

    settings = load_settings(args.config)
    candidates = discover_candidates(settings)
    dns_c = normalize_dns_candidates(candidates)
    doh_c = normalize_doh_candidates(candidates)
    all_c = dns_c + doh_c
    logger.info("Discovered %d candidates (%d DNS, %d DoH)", len(all_c), len(dns_c), len(doh_c))

    if args.output:
        import json

        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "provider": c.provider,
                "source": c.source,
                "transport": c.transport,
                "host": c.host,
                "port": c.port,
                "endpoint_url": c.endpoint_url,
                "path": c.path,
            }
            for c in all_c
        ]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote candidates to %s", args.output)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    import json

    from resolver_inventory.export.json import export_json
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates
    from resolver_inventory.validate import validate_candidates

    settings = load_settings(args.config)
    _apply_probe_corpus_override(args, settings)

    _github_group("Discovery")
    if args.input:
        raw = json.loads(Path(args.input).read_text())
        from resolver_inventory.models import Candidate

        candidates = [
            Candidate(
                provider=r.get("provider"),
                source=r.get("source", "loaded"),
                transport=r["transport"],
                endpoint_url=r.get("endpoint_url"),
                host=r["host"],
                port=r["port"],
                path=r.get("path"),
            )
            for r in raw
        ]
        logger.info("Loaded %d candidates from %s", len(candidates), args.input)
    else:
        raw_candidates = discover_candidates(settings)
        candidates = normalize_dns_candidates(raw_candidates) + normalize_doh_candidates(
            raw_candidates
        )
        logger.info("Discovered %d normalized candidates", len(candidates))
    _github_endgroup()

    _github_output("candidates_total", str(len(candidates)))

    _github_group("Validation")
    logger.info("Validating %d candidates…", len(candidates))
    results = validate_candidates(
        candidates,
        settings,
        progress_callback=_make_validation_progress_logger("validate"),
    )

    accepted = sum(1 for r in results if r.status == "accepted")
    candidate_count = sum(1 for r in results if r.status == "candidate")
    rejected = sum(1 for r in results if r.status == "rejected")
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
    _github_output("results_total", str(len(results)))
    _github_notice(
        f"Validation complete: {accepted} accepted, "
        f"{candidate_count} candidate, {rejected} rejected"
    )

    _github_group("Export")
    out_path = args.output or "outputs/validated.json"
    export_json(results, accepted_only=False, path=out_path)
    logger.info("Wrote results to %s", out_path)
    _github_output("output_path", str(Path(out_path).resolve()))
    _github_endgroup()

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
    _apply_probe_corpus_override(args, settings)
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
    export_filtered_json(filtered_candidates, path=filtered_path)
    exported_files.append(str(filtered_path))
    if "json" in formats:
        p1 = out_dir / "validated.json"
        p2 = out_dir / "accepted.json"
        export_json(results, accepted_only=False, path=p1)
        export_json(results, accepted_only=True, path=p2)
        exported_files.extend([str(p1), str(p2)])
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
    import json

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
    import json

    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.models import Candidate, ProbeResult, ValidationResult

    in_path = args.input or "outputs/validated.json"

    try:
        raw_results = json.loads(Path(in_path).read_text())
    except FileNotFoundError:
        logger.error("Input file not found: %s — run 'validate' first", in_path)
        return 1

    results: list[ValidationResult] = []
    for item in raw_results:
        c_data = item["candidate"]
        candidate = Candidate(
            provider=c_data.get("provider"),
            source=c_data.get("source", "loaded"),
            transport=c_data["transport"],
            endpoint_url=c_data.get("endpoint_url"),
            host=c_data["host"],
            port=c_data["port"],
            path=c_data.get("path"),
            bootstrap_ipv4=c_data.get("bootstrap_ipv4", []),
            bootstrap_ipv6=c_data.get("bootstrap_ipv6", []),
            tls_server_name=c_data.get("tls_server_name"),
            metadata=c_data.get("metadata", {}),
        )
        probes = [
            ProbeResult(
                ok=p["ok"],
                probe=p["probe"],
                latency_ms=p.get("latency_ms"),
                error=p.get("error"),
                details=p.get("details", {}),
            )
            for p in item.get("probes", [])
        ]
        results.append(
            ValidationResult(
                candidate=candidate,
                accepted=item["accepted"],
                score=item["score"],
                status=item["status"],
                reasons=item["reasons"],
                probes=probes,
            )
        )

    fmt = args.format
    out = args.output

    if fmt == "json":
        text = export_json(results, path=out)
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
