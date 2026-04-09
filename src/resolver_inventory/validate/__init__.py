"""Validation pipeline for resolver candidates.

Public API::

    from resolver_inventory.validate import validate_candidates
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.util.http import build_doh_client
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import render_probe_qname, resolve_baseline_answers
from resolver_inventory.validate.corpus import Corpus, CorpusEntry, build_corpus
from resolver_inventory.validate.doh import (
    _build_wire,
    _doh_post,
    _probe_nxdomain_doh,
    _probe_positive_doh,
    _probe_tls,
)
from resolver_inventory.validate.massdns_backend import (
    run_massdns_batch,
    run_massdns_rdtype_session,
)
from resolver_inventory.validate.plain_dns_backend import (
    PlainDnsProbeExecution,
    PlainDnsProbeSpec,
    plain_dns_probe_spec_from_dict,
    plain_dns_probe_spec_to_dict,
    run_python_plain_dns_batch,
    supports_massdns_phase1,
)
from resolver_inventory.validate.scorer import score
from resolver_inventory.validate.spill_store import ValidationStateStore

logger = get_logger(__name__)

ProgressCallback = Callable[["ValidationProgress"], None]
ValidationResultCallback = Callable[[ValidationResult], None]


@dataclass(frozen=True, slots=True)
class ValidationProgress:
    completed: int
    total: int
    candidate: Candidate | None = None
    result: ValidationResult | None = None
    probes_done: int = 0
    probes_total: int = 0


@dataclass(frozen=True, slots=True)
class _DoHProbeTask:
    kind: str
    candidate_idx: int
    candidate: Candidate
    entry: CorpusEntry | None


@dataclass(slots=True)
class _PreparedPlainDnsWork:
    temp_dir: Path
    rdtype_paths: dict[str, Path]
    unsupported_path: Path
    probes_expected: dict[int, int]
    total_probes: int
    massdns_supported_total: int
    python_plain_total: int


class _ValidationAccumulator:
    def __init__(
        self,
        candidates: list[Candidate],
        expected_counts: dict[int, int],
        total_probes: int,
        settings: Settings,
        emit_result: ValidationResultCallback,
        progress_callback: ProgressCallback | None,
    ) -> None:
        self.candidates = candidates
        self.expected_counts = expected_counts
        self.total_probes = total_probes
        self.settings = settings
        self.emit_result = emit_result
        self.progress_callback = progress_callback
        self.completed_counts = {idx: 0 for idx in expected_counts}
        self.store = ValidationStateStore()
        self.ready_results: dict[int, ValidationResult] = {}
        self.next_emit_idx = 0
        self.completed = 0
        self.probes_done = 0

    async def record_probe(self, candidate_idx: int, result: ProbeResult) -> None:
        self.store.append_probe_result(candidate_idx, result)
        self.completed_counts[candidate_idx] += 1
        self.probes_done += 1
        if self.completed_counts[candidate_idx] == self.expected_counts[candidate_idx]:
            probes = self.store.load_probe_results(candidate_idx)
            self.store.delete_candidate(candidate_idx)
            validation = score(self.candidates[candidate_idx], probes, self.settings)
            self.ready_results[candidate_idx] = validation
            self._emit_ready()

    def _emit_ready(self) -> None:
        while self.next_emit_idx in self.ready_results:
            result = self.ready_results.pop(self.next_emit_idx)
            self.emit_result(result)
            self.completed += 1
            if self.progress_callback is not None:
                self.progress_callback(
                    ValidationProgress(
                        completed=self.completed,
                        total=len(self.candidates),
                        candidate=result.candidate,
                        result=result,
                        probes_done=self.probes_done,
                        probes_total=self.total_probes,
                    )
                )
            self.next_emit_idx += 1

    def finalize_remaining(self) -> None:
        for candidate_idx in range(self.next_emit_idx, len(self.candidates)):
            if candidate_idx in self.ready_results:
                continue
            probes = self.store.load_probe_results(candidate_idx)
            self.store.delete_candidate(candidate_idx)
            self.ready_results[candidate_idx] = score(
                self.candidates[candidate_idx],
                probes,
                self.settings,
            )
        self._emit_ready()

    def close(self) -> None:
        self.store.close()


def _candidate_probe_count(candidate: Candidate, corpus: Corpus, rounds: int) -> int:
    round_probes = len(corpus.positive) + len(corpus.nxdomain)
    if candidate.transport == "doh":
        return 1 + (rounds * round_probes)
    return rounds * round_probes


def _iter_plain_dns_specs_for_candidate(
    candidate: Candidate,
    idx: int,
    corpus: Corpus,
    rounds: int,
) -> Iterator[PlainDnsProbeSpec]:
    seq = 0
    for round_idx in range(rounds):
        for entry in corpus.positive:
            qname = render_probe_qname(entry)
            yield PlainDnsProbeSpec(
                probe_id=f"{idx}:{round_idx}:positive:{seq}",
                kind="positive",
                candidate_idx=idx,
                candidate_transport=candidate.transport,
                host=candidate.host,
                port=candidate.port,
                qname=qname,
                rdtype=entry.rdtype.upper(),
                probe_name=f"{candidate.transport}:positive:{entry.label}",
                is_nxdomain_probe=False,
                expected_answers=list(entry.expected_answers),
                baseline_key=(
                    (qname, entry.rdtype) if entry.expected_mode == "consensus_match" else None
                ),
                entry=entry,
            )
            seq += 1
        for entry in corpus.nxdomain:
            qname = render_probe_qname(entry)
            yield PlainDnsProbeSpec(
                probe_id=f"{idx}:{round_idx}:nxdomain:{seq}",
                kind="nxdomain",
                candidate_idx=idx,
                candidate_transport=candidate.transport,
                host=candidate.host,
                port=candidate.port,
                qname=qname,
                rdtype="A",
                probe_name=f"{candidate.transport}:nxdomain:{entry.label}",
                is_nxdomain_probe=True,
                expected_answers=[],
                baseline_key=None,
                entry=entry,
            )
            seq += 1


def _iter_doh_tasks_for_candidate(
    candidate: Candidate,
    idx: int,
    corpus: Corpus,
    rounds: int,
) -> Iterator[_DoHProbeTask]:
    if candidate.transport != "doh":
        return
    yield _DoHProbeTask("doh_tls", idx, candidate, None)
    for _ in range(rounds):
        for entry in corpus.positive:
            yield _DoHProbeTask("doh_positive", idx, candidate, entry)
        for entry in corpus.nxdomain:
            yield _DoHProbeTask("doh_nxdomain", idx, candidate, entry)


def _spill_spec(handle, spec: PlainDnsProbeSpec) -> None:
    handle.write(
        json.dumps(
            plain_dns_probe_spec_to_dict(spec),
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )
    handle.write("\n")


def _iter_spilled_specs(path: Path) -> Iterator[PlainDnsProbeSpec]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield plain_dns_probe_spec_from_dict(json.loads(line))


async def _run_plain_dns_specs(
    specs: list[PlainDnsProbeSpec],
    settings: Settings,
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    on_execution: Callable[[PlainDnsProbeExecution], Any] | None = None,
) -> list[PlainDnsProbeExecution]:
    if not specs:
        return []

    backend = settings.validation.dns_backend
    logger.debug("plain DNS backend: %s", backend.kind)
    if backend.kind == "python":
        return await run_python_plain_dns_batch(
            specs,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
            parallelism=settings.validation.parallelism,
            on_execution=on_execution,
        )

    unsupported: list[PlainDnsProbeSpec] = []
    supported_by_rdtype: dict[str, list[PlainDnsProbeSpec]] = {}
    for spec in specs:
        if supports_massdns_phase1(spec):
            supported_by_rdtype.setdefault(spec.rdtype.upper(), []).append(spec)
        else:
            unsupported.append(spec)

    out: list[PlainDnsProbeExecution] = []
    if unsupported:
        out.extend(
            await run_python_plain_dns_batch(
                unsupported,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                parallelism=settings.validation.parallelism,
                on_execution=on_execution,
            )
        )

    for rdtype in ("A", "AAAA", "NS"):
        batch = supported_by_rdtype.get(rdtype)
        if not batch:
            continue
        try:
            results, _ = await run_massdns_batch(
                batch,
                config=backend,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                on_execution=on_execution,
            )
        except Exception:
            if not backend.fallback_to_python_on_error:
                raise
            results = await run_python_plain_dns_batch(
                batch,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                parallelism=settings.validation.parallelism,
                on_execution=on_execution,
            )
        out.extend(results)
    return out


def _prepare_plain_dns_work(
    candidates: list[Candidate],
    corpus: Corpus,
    rounds: int,
) -> _PreparedPlainDnsWork:
    temp_dir = Path(tempfile.mkdtemp(prefix="resolver-inventory-plain-"))
    rdtype_paths: dict[str, Path] = {}
    rdtype_handles: dict[str, Any] = {}
    unsupported_path = temp_dir / "plain-python.ndjson"
    unsupported_handle = unsupported_path.open("w", encoding="utf-8")
    probes_expected: dict[int, int] = {}
    total_probes = 0
    massdns_supported_total = 0
    python_plain_total = 0

    try:
        for idx, candidate in enumerate(candidates):
            probes_expected[idx] = _candidate_probe_count(candidate, corpus, rounds)
            total_probes += probes_expected[idx]
            if candidate.transport == "doh":
                continue
            for spec in _iter_plain_dns_specs_for_candidate(candidate, idx, corpus, rounds):
                if supports_massdns_phase1(spec):
                    path = rdtype_paths.setdefault(
                        spec.rdtype,
                        temp_dir / f"plain-{spec.rdtype}.ndjson",
                    )
                    handle = rdtype_handles.get(spec.rdtype)
                    if handle is None:
                        handle = path.open("w", encoding="utf-8")
                        rdtype_handles[spec.rdtype] = handle
                    _spill_spec(handle, spec)
                    massdns_supported_total += 1
                else:
                    _spill_spec(unsupported_handle, spec)
                    python_plain_total += 1
    finally:
        unsupported_handle.close()
        for handle in rdtype_handles.values():
            handle.close()

    return _PreparedPlainDnsWork(
        temp_dir=temp_dir,
        rdtype_paths=rdtype_paths,
        unsupported_path=unsupported_path,
        probes_expected=probes_expected,
        total_probes=total_probes,
        massdns_supported_total=massdns_supported_total,
        python_plain_total=python_plain_total,
    )


async def _run_python_plain_specs_from_file(
    path: Path,
    settings: Settings,
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    on_execution: Callable[[PlainDnsProbeExecution], Any],
) -> None:
    batch: list[PlainDnsProbeSpec] = []
    chunk_size = max(100, settings.validation.parallelism * 20)
    for spec in _iter_spilled_specs(path):
        batch.append(spec)
        if len(batch) >= chunk_size:
            await run_python_plain_dns_batch(
                batch,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                parallelism=settings.validation.parallelism,
                on_execution=on_execution,
            )
            batch = []
    if batch:
        await run_python_plain_dns_batch(
            batch,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
            parallelism=settings.validation.parallelism,
            on_execution=on_execution,
        )


async def _execute_doh_probe(
    task: _DoHProbeTask,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    doh_clients: dict[int, Any],
) -> ProbeResult:
    candidate = task.candidate
    if task.kind == "doh_tls":
        return await _probe_tls(candidate, timeout_s)
    if task.kind == "doh_positive":
        assert task.entry is not None
        return await _probe_positive_doh(
            task.entry,
            doh_clients[task.candidate_idx],
            candidate.endpoint_url or "",
            timeout_s,
            baseline_resolvers,
            baseline_cache,
        )
    if task.kind == "doh_nxdomain":
        assert task.entry is not None
        return await _probe_nxdomain_doh(
            task.entry,
            doh_clients[task.candidate_idx],
            candidate.endpoint_url or "",
        )
    from resolver_inventory.validate.base import fail_probe

    return fail_probe(f"unknown:{task.kind}", "internal_error")


async def _run_doh_phase(
    candidates: list[Candidate],
    settings: Settings,
    corpus: Corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    accumulator: _ValidationAccumulator,
) -> None:
    timeout_s = settings.validation.timeout_ms / 1000.0
    baseline_resolvers = settings.validation.baseline_resolvers
    window_size = max(1, settings.validation.doh_parallelism)

    for start_idx in range(0, len(candidates), window_size):
        window = candidates[start_idx : start_idx + window_size]
        doh_clients: dict[int, Any] = {}
        tasks: list[_DoHProbeTask] = []
        for offset, candidate in enumerate(window):
            idx = start_idx + offset
            if candidate.transport != "doh":
                continue
            doh_clients[idx] = build_doh_client(timeout_s=timeout_s)
            tasks.extend(
                _iter_doh_tasks_for_candidate(
                    candidate,
                    idx,
                    corpus,
                    settings.validation.rounds,
                )
            )
        if not tasks:
            for client in doh_clients.values():
                await client.aclose()
            continue

        async def _warmup(client: Any, url: str) -> None:
            try:
                wire = _build_wire("a.root-servers.net.", "A")
                await _doh_post(client, url, wire)
            except Exception:
                pass

        await asyncio.gather(
            *(_warmup(doh_clients[idx], candidates[idx].endpoint_url or "") for idx in doh_clients)
        )

        queue: asyncio.Queue[_DoHProbeTask] = asyncio.Queue()
        for task in tasks:
            queue.put_nowait(task)

        async def worker(
            queue: asyncio.Queue[_DoHProbeTask] = queue,
            doh_clients: dict[int, Any] = doh_clients,
        ) -> None:
            while True:
                try:
                    task = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    result = await _execute_doh_probe(
                        task,
                        timeout_s,
                        baseline_resolvers,
                        baseline_cache,
                        doh_clients,
                    )
                    await accumulator.record_probe(task.candidate_idx, result)
                finally:
                    queue.task_done()

        worker_count = max(1, min(settings.validation.doh_parallelism, len(tasks)))
        worker_tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
        try:
            await queue.join()
        finally:
            for wt in worker_tasks:
                wt.cancel()
            for wt in worker_tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await wt
            for client in doh_clients.values():
                await client.aclose()


async def _validate_candidates_async(
    candidates: list[Candidate],
    settings: Settings,
    corpus: Corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    *,
    emit_result: ValidationResultCallback,
    progress_callback: ProgressCallback | None,
) -> None:
    if not candidates:
        return

    prepared = _prepare_plain_dns_work(candidates, corpus, settings.validation.rounds)
    accumulator = _ValidationAccumulator(
        candidates,
        prepared.probes_expected,
        prepared.total_probes,
        settings,
        emit_result,
        progress_callback,
    )
    timeout_s = settings.validation.timeout_ms / 1000.0
    baseline_resolvers = settings.validation.baseline_resolvers

    logger.debug("plain DNS backend: %s", settings.validation.dns_backend.kind)
    logger.debug(
        "plain DNS routing: total=%d massdns=%d python_unsupported=%d",
        prepared.massdns_supported_total + prepared.python_plain_total,
        prepared.massdns_supported_total,
        prepared.python_plain_total,
    )

    try:
        if settings.validation.dns_backend.kind == "massdns":
            summary = {
                "massdns_sessions_started": 0,
                "massdns_sessions_restarted": 0,
                "massdns_sessions_succeeded": 0,
                "massdns_sessions_failed": 0,
                "massdns_probes_sent": 0,
                "massdns_results_parsed": 0,
                "massdns_terminal_failures_matched": 0,
                "massdns_unmatched_results": 0,
            }
            for rdtype in ("A", "AAAA", "NS"):
                path = prepared.rdtype_paths.get(rdtype)
                if path is None or not path.exists():
                    continue
                summary["massdns_sessions_started"] += 1
                _, metrics = await run_massdns_rdtype_session(
                    lambda path=path: _iter_spilled_specs(path),
                    rdtype=rdtype,
                    config=settings.validation.dns_backend,
                    timeout_s=timeout_s,
                    baseline_resolvers=baseline_resolvers,
                    baseline_cache=baseline_cache,
                    on_execution=lambda execution: accumulator.record_probe(
                        execution.spec.candidate_idx, execution.result
                    ),
                )
                logger.debug(
                    (
                        "massdns session rdtype=%s sent=%d parsed=%d stdout_lines=%d "
                        "stderr_lines=%d unmatched=%d terminal_failures=%d exit_code=%d restarts=%d"
                    ),
                    rdtype,
                    metrics.probes_sent,
                    metrics.parsed_results,
                    metrics.stdout_lines,
                    metrics.stderr_lines,
                    metrics.unmatched_results,
                    metrics.terminal_failures_matched,
                    metrics.exit_code,
                    metrics.restarts,
                )
                summary["massdns_sessions_restarted"] += metrics.restarts
                summary["massdns_probes_sent"] += metrics.probes_sent
                summary["massdns_results_parsed"] += metrics.parsed_results
                summary["massdns_terminal_failures_matched"] += metrics.terminal_failures_matched
                summary["massdns_unmatched_results"] += metrics.unmatched_results
                if metrics.exit_code == 0:
                    summary["massdns_sessions_succeeded"] += 1
                else:
                    summary["massdns_sessions_failed"] += 1
            logger.debug("massdns summary: %s", summary)
        else:
            logger.debug("massdns summary: backend disabled")

        await _run_python_plain_specs_from_file(
            prepared.unsupported_path,
            settings,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
            on_execution=lambda execution: accumulator.record_probe(
                execution.spec.candidate_idx, execution.result
            ),
        )
        await _run_doh_phase(candidates, settings, corpus, baseline_cache, accumulator)
        accumulator.finalize_remaining()
    finally:
        accumulator.close()
        with contextlib.suppress(Exception):
            for child in prepared.temp_dir.iterdir():
                child.unlink()
        with contextlib.suppress(Exception):
            prepared.temp_dir.rmdir()


def validate_candidates_stream(
    candidates: list[Candidate],
    emit_result: ValidationResultCallback,
    settings: Settings | None = None,
    progress_callback: ProgressCallback | None = None,
) -> None:
    if settings is None:
        from resolver_inventory.settings import Settings as S

        settings = S()

    async def _run() -> None:
        corpus = build_corpus(settings.validation.corpus)
        baseline_cache: dict[tuple[str, str], list[str]] = {}
        timeout_s = settings.validation.timeout_ms / 1000.0

        for entry in corpus.positive:
            if entry.expected_mode == "consensus_match" and entry.qname:
                with contextlib.suppress(Exception):
                    await resolve_baseline_answers(
                        entry.qname,
                        entry.rdtype,
                        settings.validation.baseline_resolvers,
                        timeout_s,
                        baseline_cache,
                    )

        await _validate_candidates_async(
            candidates,
            settings,
            corpus,
            baseline_cache,
            emit_result=emit_result,
            progress_callback=progress_callback,
        )

    asyncio.run(_run())


def validate_candidates_iter(
    candidates: list[Candidate],
    settings: Settings | None = None,
    progress_callback: ProgressCallback | None = None,
) -> Iterator[ValidationResult]:
    results: list[ValidationResult] = []
    validate_candidates_stream(
        candidates,
        lambda result: results.append(result),
        settings=settings,
        progress_callback=progress_callback,
    )
    yield from results


def validate_candidates(
    candidates: list[Candidate],
    settings: Settings | None = None,
    progress_callback: ProgressCallback | None = None,
) -> list[ValidationResult]:
    return list(validate_candidates_iter(candidates, settings, progress_callback))
