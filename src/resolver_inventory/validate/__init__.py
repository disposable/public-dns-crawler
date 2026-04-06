"""Validation pipeline for resolver candidates.

Public API::

    from resolver_inventory.validate import validate_candidates
"""

from __future__ import annotations

import asyncio
import contextlib
import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.util.http import build_doh_client
from resolver_inventory.validate.base import resolve_baseline_answers
from resolver_inventory.validate.corpus import CorpusEntry, build_corpus
from resolver_inventory.validate.dns_plain import _probe_nxdomain, _probe_positive
from resolver_inventory.validate.doh import (
    _build_wire,
    _doh_post,
    _probe_nxdomain_doh,
    _probe_positive_doh,
    _probe_tls,
)
from resolver_inventory.validate.scorer import score

ProgressCallback = Callable[["ValidationProgress"], None]


@dataclass(frozen=True, slots=True)
class ValidationProgress:
    completed: int
    total: int
    candidate: Candidate
    result: ValidationResult


# A probe task describes one individual probe to run.
# kind is one of: dns_positive, dns_nxdomain, doh_positive, doh_nxdomain, doh_tls
@dataclass(slots=True)
class _ProbeTask:
    kind: str
    candidate_idx: int
    candidate: Candidate
    entry: CorpusEntry | None  # None for doh_tls


async def _run_flat_queue(
    candidates: list[Candidate],
    settings: Settings,
    corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    *,
    progress_callback: ProgressCallback | None = None,
    parallelism: int,
    completed_offset: int = 0,
    total_override: int | None = None,
) -> list[ValidationResult]:
    if not candidates:
        return []

    timeout_s = settings.validation.timeout_ms / 1000.0
    rounds = settings.validation.rounds
    baseline_resolvers = settings.validation.baseline_resolvers
    overall_total = total_override if total_override is not None else len(candidates)

    # Pre-create one DoH client per DoH candidate so probes share a single
    # HTTP/2 connection per endpoint.
    doh_clients: dict[int, Any] = {}
    for idx, candidate in enumerate(candidates):
        if candidate.transport == "doh":
            doh_clients[idx] = build_doh_client(timeout_s=timeout_s)

    # Warm up all DoH connections concurrently before the main queue starts so
    # the TLS handshake cost is not included in any probe latency measurement.
    if doh_clients:

        async def _warmup(client: Any, url: str) -> None:
            try:
                wire = _build_wire("a.root-servers.net.", "A")
                await _doh_post(client, url, wire)
            except Exception:
                pass

        await asyncio.gather(
            *(_warmup(doh_clients[idx], candidates[idx].endpoint_url or "") for idx in doh_clients)
        )

    # Build one task per (candidate * probe * round), shuffled so probes for
    # any single resolver are spread across the entire run instead of firing
    # back-to-back.
    tasks: list[_ProbeTask] = []
    probes_expected: list[int] = []

    for idx, candidate in enumerate(candidates):
        count = 0
        if candidate.transport == "doh":
            tasks.append(_ProbeTask("doh_tls", idx, candidate, None))
            count += 1
            for _ in range(rounds):
                for entry in corpus.positive:
                    tasks.append(_ProbeTask("doh_positive", idx, candidate, entry))
                    count += 1
                for entry in corpus.nxdomain:
                    tasks.append(_ProbeTask("doh_nxdomain", idx, candidate, entry))
                    count += 1
        else:
            for _ in range(rounds):
                for entry in corpus.positive:
                    tasks.append(_ProbeTask("dns_positive", idx, candidate, entry))
                    count += 1
                for entry in corpus.nxdomain:
                    tasks.append(_ProbeTask("dns_nxdomain", idx, candidate, entry))
                    count += 1
        probes_expected.append(count)

    random.shuffle(tasks)

    # Per-candidate probe result accumulation.
    collected: list[list[ProbeResult]] = [[] for _ in candidates]
    probe_counts: list[int] = [0] * len(candidates)
    results: list[ValidationResult | None] = [None] * len(candidates)
    completed_count = 0

    queue: asyncio.Queue[_ProbeTask] = asyncio.Queue()
    for task in tasks:
        queue.put_nowait(task)

    async def worker() -> None:
        nonlocal completed_count
        while True:
            try:
                task = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                result = await _execute_probe(
                    task, timeout_s, baseline_resolvers, baseline_cache, doh_clients
                )
                collected[task.candidate_idx].append(result)
                probe_counts[task.candidate_idx] += 1

                if probe_counts[task.candidate_idx] == probes_expected[task.candidate_idx]:
                    validation_result = score(
                        candidates[task.candidate_idx],
                        collected[task.candidate_idx],
                        settings,
                    )
                    results[task.candidate_idx] = validation_result
                    completed_count += 1
                    if progress_callback is not None:
                        progress_callback(
                            ValidationProgress(
                                completed=completed_offset + completed_count,
                                total=overall_total,
                                candidate=candidates[task.candidate_idx],
                                result=validation_result,
                            )
                        )
            finally:
                queue.task_done()

    worker_count = max(1, min(parallelism, len(tasks)))
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

    return [r for r in results if r is not None]


async def _execute_probe(
    task: _ProbeTask,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    doh_clients: dict[int, Any],
) -> ProbeResult:
    candidate = task.candidate
    if task.kind == "dns_positive":
        assert task.entry is not None
        return await _probe_positive(
            task.entry,
            candidate.host,
            candidate.port,
            candidate.transport,
            timeout_s,
            baseline_resolvers,
            baseline_cache,
        )
    elif task.kind == "dns_nxdomain":
        assert task.entry is not None
        return await _probe_nxdomain(
            task.entry,
            candidate.host,
            candidate.port,
            candidate.transport,
            timeout_s,
        )
    elif task.kind == "doh_tls":
        return await _probe_tls(candidate, timeout_s)
    elif task.kind == "doh_positive":
        assert task.entry is not None
        return await _probe_positive_doh(
            task.entry,
            doh_clients[task.candidate_idx],
            candidate.endpoint_url or "",
            timeout_s,
            baseline_resolvers,
            baseline_cache,
        )
    elif task.kind == "doh_nxdomain":
        assert task.entry is not None
        return await _probe_nxdomain_doh(
            task.entry,
            doh_clients[task.candidate_idx],
            candidate.endpoint_url or "",
        )
    else:
        from resolver_inventory.validate.base import fail_probe

        return fail_probe(f"unknown:{task.kind}", "internal_error")


def validate_candidates(
    candidates: list[Candidate],
    settings: Settings | None = None,
    progress_callback: ProgressCallback | None = None,
) -> list[ValidationResult]:
    """Run all validation probes against every candidate. Synchronous entry point."""
    if settings is None:
        from resolver_inventory.settings import Settings as S

        settings = S()

    async def _run() -> list[ValidationResult]:
        corpus = build_corpus(settings.validation.corpus)
        baseline_cache: dict[tuple[str, str], list[str]] = {}
        timeout_s = settings.validation.timeout_ms / 1000.0

        # Pre-populate baseline cache for fixed-qname consensus_match entries.
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

        return await _run_flat_queue(
            candidates,
            settings,
            corpus,
            baseline_cache,
            progress_callback=progress_callback,
            parallelism=settings.validation.parallelism,
        )

    return asyncio.run(_run())
