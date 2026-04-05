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
        )

    return score(candidate, probes, settings)


async def _validate_all(
    candidates: list[Candidate],
    settings: Settings,
    progress_callback: ProgressCallback | None = None,
) -> list[ValidationResult]:
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

    total = len(candidates)
    if total == 0:
        return []

    # Shuffle so we don't hit any single provider or IP block with sequential bursts.
    shuffled = list(candidates)
    random.shuffle(shuffled)

    work_queue: asyncio.Queue[tuple[int, Candidate]] = asyncio.Queue()
    for index, candidate in enumerate(shuffled):
        work_queue.put_nowait((index, candidate))

    results: list[ValidationResult | None] = [None] * total
    completed = 0

    async def worker() -> None:
        nonlocal completed
        while True:
            try:
                index, candidate = work_queue.get_nowait()
            except asyncio.QueueEmpty:
                return

            try:
                result = await _validate_one(candidate, settings, corpus, baseline_cache)
                results[index] = result
                completed += 1
                if progress_callback is not None:
                    progress_callback(
                        ValidationProgress(
                            completed=completed,
                            total=total,
                            candidate=candidate,
                            result=result,
                        )
                    )
            finally:
                work_queue.task_done()

    worker_count = max(1, min(settings.validation.parallelism, total))
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
    return asyncio.run(_validate_all(candidates, settings, progress_callback=progress_callback))
