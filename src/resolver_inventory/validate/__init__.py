"""Validation pipeline for resolver candidates.

Public API::

    from resolver_inventory.validate import validate_candidates
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.util.http import build_doh_client
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import render_probe_qname, resolve_baseline_answers
from resolver_inventory.validate.corpus import Corpus, CorpusEntry, build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate as validate_dns_candidate
from resolver_inventory.validate.doh import (
    _build_wire,
    _doh_post,
    _probe_nxdomain_doh,
    _probe_positive_doh,
    _probe_tls,
)
from resolver_inventory.validate.massdns_backend import (
    group_probe_specs_for_massdns,
    run_massdns_batch,
)
from resolver_inventory.validate.plain_dns_backend import (
    PlainDnsProbeExecution,
    PlainDnsProbeSpec,
    run_python_plain_dns_batch,
    supports_massdns_phase1,
)
from resolver_inventory.validate.scorer import score

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


@dataclass(slots=True)
class _DoHProbeTask:
    kind: str
    candidate_idx: int
    candidate: Candidate
    entry: CorpusEntry | None


@dataclass(slots=True)
class _ProbeWorkload:
    plain_specs: list[PlainDnsProbeSpec]
    doh_tasks: list[_DoHProbeTask]
    probes_expected: dict[int, int]


def _candidate_probe_count(candidate: Candidate, corpus: Corpus, rounds: int) -> int:
    round_probes = len(corpus.positive) + len(corpus.nxdomain)
    if candidate.transport == "doh":
        return 1 + (rounds * round_probes)
    return rounds * round_probes


def _build_probe_workload(
    candidates: list[Candidate],
    corpus: Corpus,
    rounds: int,
    *,
    start_idx: int,
) -> _ProbeWorkload:
    plain_specs: list[PlainDnsProbeSpec] = []
    doh_tasks: list[_DoHProbeTask] = []
    probes_expected: dict[int, int] = {}

    for offset, candidate in enumerate(candidates):
        idx = start_idx + offset
        count = 0
        if candidate.transport == "doh":
            doh_tasks.append(_DoHProbeTask("doh_tls", idx, candidate, None))
            count += 1
            for _ in range(rounds):
                for entry in corpus.positive:
                    doh_tasks.append(_DoHProbeTask("doh_positive", idx, candidate, entry))
                    count += 1
                for entry in corpus.nxdomain:
                    doh_tasks.append(_DoHProbeTask("doh_nxdomain", idx, candidate, entry))
                    count += 1
        else:
            seq = 0
            for round_idx in range(rounds):
                for entry in corpus.positive:
                    qname = render_probe_qname(entry)
                    plain_specs.append(
                        PlainDnsProbeSpec(
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
                            baseline_key=(qname, entry.rdtype)
                            if entry.expected_mode == "consensus_match"
                            else None,
                            entry=entry,
                        )
                    )
                    count += 1
                    seq += 1
                for entry in corpus.nxdomain:
                    qname = render_probe_qname(entry)
                    plain_specs.append(
                        PlainDnsProbeSpec(
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
                    )
                    count += 1
                    seq += 1
        probes_expected[idx] = count

    return _ProbeWorkload(
        plain_specs=plain_specs,
        doh_tasks=doh_tasks,
        probes_expected=probes_expected,
    )


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
    massdns_specs: list[PlainDnsProbeSpec] = []
    for spec in specs:
        if supports_massdns_phase1(spec):
            massdns_specs.append(spec)
        else:
            unsupported.append(spec)

    logger.debug(
        "plain DNS routing: total=%d massdns=%d python_unsupported=%d",
        len(specs),
        len(massdns_specs),
        len(unsupported),
    )

    out: list[PlainDnsProbeExecution] = []
    python_fallback_probes = len(unsupported)
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

    batches = group_probe_specs_for_massdns(
        massdns_specs,
        batch_max_queries=backend.batch_max_queries,
    )
    logger.debug("massdns batches started: %d", len(batches))
    batches_succeeded = 0
    batches_failed = 0

    for batch in batches:
        try:
            batch_results, metrics = await run_massdns_batch(
                batch,
                config=backend,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                on_execution=on_execution,
            )
            logger.debug(
                (
                    "massdns batch rdtype=%s sent=%d parsed=%d stdout_lines=%d "
                    "stderr_lines=%d unmatched=%d exit_code=%d"
                ),
                batch[0].rdtype if batch else "?",
                len(batch),
                metrics.parsed_results,
                metrics.stdout_lines,
                metrics.stderr_lines,
                metrics.unmatched_results,
                metrics.exit_code,
            )
            out.extend(batch_results)
            batches_succeeded += 1
        except FileNotFoundError as exc:
            batches_failed += 1
            if not backend.fallback_to_python_on_error:
                raise RuntimeError(f"massdns binary not found: {backend.massdns_bin}") from exc
            python_fallback_probes += len(batch)
            out.extend(
                await run_python_plain_dns_batch(
                    batch,
                    timeout_s=timeout_s,
                    baseline_resolvers=baseline_resolvers,
                    baseline_cache=baseline_cache,
                    parallelism=settings.validation.parallelism,
                    on_execution=on_execution,
                )
            )
        except Exception:
            batches_failed += 1
            if not backend.fallback_to_python_on_error:
                raise
            python_fallback_probes += len(batch)
            out.extend(
                await run_python_plain_dns_batch(
                    batch,
                    timeout_s=timeout_s,
                    baseline_resolvers=baseline_resolvers,
                    baseline_cache=baseline_cache,
                    parallelism=settings.validation.parallelism,
                    on_execution=on_execution,
                )
            )

    logger.debug(
        "massdns summary: batches_succeeded=%d batches_failed=%d python_fallback_probes=%d",
        batches_succeeded,
        batches_failed,
        python_fallback_probes,
    )
    return out


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


async def _run_window(
    window_candidates: list[Candidate],
    settings: Settings,
    corpus: Corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    *,
    start_idx: int,
    total_candidates: int,
    total_probes: int,
    completed_before: int,
    probes_done_before: int,
    emit_result: ValidationResultCallback,
    progress_callback: ProgressCallback | None,
) -> tuple[int, int]:
    timeout_s = settings.validation.timeout_ms / 1000.0
    rounds = settings.validation.rounds
    baseline_resolvers = settings.validation.baseline_resolvers

    workload = _build_probe_workload(
        window_candidates,
        corpus,
        rounds,
        start_idx=start_idx,
    )
    collected: dict[int, list[ProbeResult]] = {
        start_idx + offset: [] for offset in range(len(window_candidates))
    }
    probe_counts: dict[int, int] = {idx: 0 for idx in collected}
    ready_results: dict[int, ValidationResult] = {}
    completed_count = completed_before
    probes_done = probes_done_before
    next_emit_idx = start_idx

    def _candidate_at(global_idx: int) -> Candidate:
        return window_candidates[global_idx - start_idx]

    def _emit_ready() -> None:
        nonlocal next_emit_idx, completed_count
        while next_emit_idx in ready_results:
            result = ready_results.pop(next_emit_idx)
            emit_result(result)
            completed_count += 1
            if progress_callback is not None:
                progress_callback(
                    ValidationProgress(
                        completed=completed_count,
                        total=total_candidates,
                        candidate=result.candidate,
                        result=result,
                        probes_done=probes_done,
                        probes_total=total_probes,
                    )
                )
            next_emit_idx += 1

    async def _record_probe(candidate_idx: int, result: ProbeResult) -> None:
        nonlocal probes_done
        collected[candidate_idx].append(result)
        probe_counts[candidate_idx] += 1
        probes_done += 1
        if probe_counts[candidate_idx] == workload.probes_expected[candidate_idx]:
            candidate = _candidate_at(candidate_idx)
            candidate_probes = collected.pop(candidate_idx)
            probe_counts.pop(candidate_idx, None)
            ready_results[candidate_idx] = score(candidate, candidate_probes, settings)
            _emit_ready()

    async def _record_execution(execution: PlainDnsProbeExecution) -> None:
        await _record_probe(execution.spec.candidate_idx, execution.result)

    await _run_plain_dns_specs(
        workload.plain_specs,
        settings,
        timeout_s=timeout_s,
        baseline_resolvers=baseline_resolvers,
        baseline_cache=baseline_cache,
        on_execution=_record_execution,
    )

    doh_clients: dict[int, Any] = {}
    for offset, candidate in enumerate(window_candidates):
        if candidate.transport == "doh":
            doh_clients[start_idx + offset] = build_doh_client(timeout_s=timeout_s)
    if doh_clients:

        async def _warmup(client: Any, url: str) -> None:
            try:
                wire = _build_wire("a.root-servers.net.", "A")
                await _doh_post(client, url, wire)
            except Exception:
                pass

        await asyncio.gather(
            *(
                _warmup(doh_clients[idx], _candidate_at(idx).endpoint_url or "")
                for idx in doh_clients
            )
        )

    queue: asyncio.Queue[_DoHProbeTask] = asyncio.Queue()
    for task in workload.doh_tasks:
        queue.put_nowait(task)

    async def worker() -> None:
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
                await _record_probe(task.candidate_idx, result)
            finally:
                queue.task_done()

    async def _heartbeat(interval_s: float = 30.0) -> None:
        while True:
            await asyncio.sleep(interval_s)
            if progress_callback is not None:
                progress_callback(
                    ValidationProgress(
                        completed=completed_count,
                        total=total_candidates,
                        probes_done=probes_done,
                        probes_total=total_probes,
                    )
                )

    worker_count = max(1, min(settings.validation.doh_parallelism, len(workload.doh_tasks)))
    worker_tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
    heartbeat_task = asyncio.create_task(_heartbeat())
    try:
        await queue.join()
    finally:
        heartbeat_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat_task
        for wt in worker_tasks:
            wt.cancel()
        for wt in worker_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await wt
        for client in doh_clients.values():
            await client.aclose()

    for candidate_idx in sorted(collected):
        candidate = _candidate_at(candidate_idx)
        ready_results[candidate_idx] = score(candidate, collected[candidate_idx], settings)
    _emit_ready()
    return completed_count, probes_done


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

    window_size = max(1, settings.validation.parallelism)
    rounds = settings.validation.rounds
    total_probes = sum(
        _candidate_probe_count(candidate, corpus, rounds) for candidate in candidates
    )
    completed_count = 0
    probes_done = 0

    for start_idx in range(0, len(candidates), window_size):
        window = candidates[start_idx : start_idx + window_size]
        completed_count, probes_done = await _run_window(
            window,
            settings,
            corpus,
            baseline_cache,
            start_idx=start_idx,
            total_candidates=len(candidates),
            total_probes=total_probes,
            completed_before=completed_count,
            probes_done_before=probes_done,
            emit_result=emit_result,
            progress_callback=progress_callback,
        )


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
    """Run all validation probes against every candidate. Synchronous entry point."""
    return list(validate_candidates_iter(candidates, settings, progress_callback))
