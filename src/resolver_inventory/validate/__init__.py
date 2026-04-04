"""Validation pipeline for resolver candidates.

Public API::

    from resolver_inventory.validate import validate_candidates
"""

from __future__ import annotations

import asyncio

from resolver_inventory.models import Candidate, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate
from resolver_inventory.validate.doh import validate_doh_candidate
from resolver_inventory.validate.scorer import score


async def _validate_one(
    candidate: Candidate,
    settings: Settings,
    corpus,
) -> ValidationResult:
    timeout_s = settings.validation.timeout_ms / 1000.0
    rounds = settings.validation.rounds

    if candidate.transport in ("dns-udp", "dns-tcp"):
        probes = await validate_dns_candidate(candidate, corpus, timeout_s=timeout_s, rounds=rounds)
    else:
        probes = await validate_doh_candidate(candidate, corpus, timeout_s=timeout_s, rounds=rounds)

    return score(candidate, probes, settings)


async def _validate_all(
    candidates: list[Candidate],
    settings: Settings,
) -> list[ValidationResult]:
    corpus = build_corpus(settings.validation.corpus)
    sem = asyncio.Semaphore(settings.validation.parallelism)

    async def bounded(c: Candidate) -> ValidationResult:
        async with sem:
            return await _validate_one(c, settings, corpus)

    tasks = [bounded(c) for c in candidates]
    return list(await asyncio.gather(*tasks))


def validate_candidates(
    candidates: list[Candidate],
    settings: Settings | None = None,
) -> list[ValidationResult]:
    """Run all validation probes against every candidate. Synchronous entry point."""
    if settings is None:
        from resolver_inventory.settings import Settings as S

        settings = S()
    return asyncio.run(_validate_all(candidates, settings))
