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

from resolver_inventory.models import Candidate, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.util.http import build_doh_client
from resolver_inventory.validate.base import resolve_baseline_answers
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate
from resolver_inventory.validate.doh import validate_doh_candidate
from resolver_inventory.validate.scorer import score

ProgressCallback = Callable[["ValidationProgress"], None]


@dataclass(frozen=True, slots=True)
class ValidationProgress:
    completed: int
    total: int
    candidate: Candidate
    result: ValidationResult


async def _validate_one(
    candidate: Candidate,
    settings: Settings,
    corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    *,
    doh_client=None,
) -> ValidationResult:
    timeout_s = settings.validation.timeout_ms / 1000.0
    rounds = settings.validation.rounds

    if candidate.transport in ("dns-udp", "dns-tcp"):
        probes = await validate_dns_candidate(
            candidate,
            corpus,
            timeout_s=timeout_s,
            rounds=rounds,
            baseline_resolvers=settings.validation.baseline_resolvers,
            baseline_cache=baseline_cache,
        )
    else:
        probes = await validate_doh_candidate(
            candidate,
            corpus,
            timeout_s=timeout_s,
            rounds=rounds,
            baseline_resolvers=settings.validation.baseline_resolvers,
            baseline_cache=baseline_cache,
            client=doh_client,
        )

    return score(candidate, probes, settings)


async def _validate_all(
    candidates: list[Candidate],
    settings: Settings,
    corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    progress_callback: ProgressCallback | None = None,
    *,
    parallelism: int | None = None,
    completed_offset: int = 0,
    total_override: int | None = None,
) -> list[ValidationResult]:
    timeout_s = settings.validation.timeout_ms / 1000.0
    batch_total = len(candidates)
    overall_total = total_override if total_override is not None else batch_total
    if batch_total == 0:
        return []

    return await _validate_batch(
        candidates,
        settings,
        corpus,
        baseline_cache,
        timeout_s=timeout_s,
        progress_callback=progress_callback,
        parallelism=parallelism,
        completed_offset=completed_offset,
        total_override=overall_total,
    )


async def _validate_batch(
    candidates: list[Candidate],
    settings: Settings,
    corpus,
    baseline_cache: dict[tuple[str, str], list[str]],
    *,
    timeout_s: float,
    progress_callback: ProgressCallback | None = None,
    parallelism: int | None = None,
    completed_offset: int = 0,
    total_override: int | None = None,
) -> list[ValidationResult]:
    batch_total = len(candidates)
    overall_total = total_override if total_override is not None else batch_total

    # Shuffle so we don't hit any single provider or IP block with sequential bursts.
    shuffled = list(candidates)
    random.shuffle(shuffled)

    work_queue: asyncio.Queue[tuple[int, Candidate]] = asyncio.Queue()
    for index, candidate in enumerate(shuffled):
        work_queue.put_nowait((index, candidate))

    results: list[ValidationResult | None] = [None] * batch_total
    completed = 0

    async def worker() -> None:
        nonlocal completed
        doh_client = None
        try:
            while True:
                try:
                    index, candidate = work_queue.get_nowait()
                except asyncio.QueueEmpty:
                    return

                try:
                    if candidate.transport == "doh" and doh_client is None:
                        doh_client = build_doh_client(timeout_s=timeout_s)
                    result = await _validate_one(
                        candidate,
                        settings,
                        corpus,
                        baseline_cache,
                        doh_client=doh_client if candidate.transport == "doh" else None,
                    )
                    results[index] = result
                    completed += 1
                    if progress_callback is not None:
                        progress_callback(
                            ValidationProgress(
                                completed=completed_offset + completed,
                                total=overall_total,
                                candidate=candidate,
                                result=result,
                            )
                        )
                finally:
                    work_queue.task_done()
        finally:
            if doh_client is not None:
                await doh_client.aclose()

    effective_parallelism = settings.validation.parallelism if parallelism is None else parallelism
    worker_count = max(1, min(effective_parallelism, batch_total))
    tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
    try:
        await work_queue.join()
    finally:
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task

    return [result for result in results if result is not None]


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

        # Pre-populate baseline cache for fixed-qname consensus_match entries so that
        # parallel probes within a candidate all hit the cache instead of each firing
        # redundant baseline queries.
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

        dns_candidates = [candidate for candidate in candidates if candidate.transport != "doh"]
        doh_candidates = [candidate for candidate in candidates if candidate.transport == "doh"]

        dns_results = await _validate_all(
            dns_candidates,
            settings,
            corpus,
            baseline_cache,
            progress_callback=progress_callback,
            parallelism=settings.validation.parallelism,
            completed_offset=0,
            total_override=len(candidates),
        )
        doh_results = await _validate_all(
            doh_candidates,
            settings,
            corpus,
            baseline_cache,
            progress_callback=progress_callback,
            parallelism=settings.validation.doh_parallelism,
            completed_offset=len(dns_results),
            total_override=len(candidates),
        )
        return [*dns_results, *doh_results]

    return asyncio.run(_run())
