"""Logical and baseline-backed validation for generated probe corpora."""

from __future__ import annotations

import asyncio
import secrets
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import Protocol

import dns.asyncquery
import dns.message
import dns.rdatatype

from resolver_inventory.probe_corpus.models import (
    GeneratedProbeCandidate,
    GeneratedProbeValidation,
    ProbeGenerationReport,
)
from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition
from resolver_inventory.settings import ProbeCorpusConfig
from resolver_inventory.validate.base import normalize_answer_set, normalize_expected_answers


@dataclass(slots=True)
class BaselineQueryResult:
    resolver: str
    qname: str
    qtype: str
    rcode: str
    answers: list[str] = field(default_factory=list)
    error: str | None = None


class BaselineResolverClient(Protocol):
    async def query(self, resolver: str, qname: str, qtype: str) -> BaselineQueryResult:
        """Query one configured baseline resolver."""
        ...


@dataclass(slots=True)
class UdpBaselineResolverClient:
    timeout_s: float = 2.0

    async def query(self, resolver: str, qname: str, qtype: str) -> BaselineQueryResult:
        host, port = _parse_resolver(resolver)
        msg = dns.message.make_query(qname, dns.rdatatype.from_text(qtype))
        msg.id = 0
        try:
            response = await dns.asyncquery.udp(msg, host, port=port, timeout=self.timeout_s)
        except Exception as exc:
            return BaselineQueryResult(
                resolver=resolver,
                qname=qname,
                qtype=qtype,
                rcode="ERROR",
                error=str(exc),
            )
        return BaselineQueryResult(
            resolver=resolver,
            qname=qname,
            qtype=qtype,
            rcode=dns.rcode.to_text(response.rcode()),  # type: ignore[attr-defined]
            answers=normalize_answer_set(response, qtype),
        )


def validate_generated_probe_corpus(
    corpus: ProbeCorpus,
    *,
    min_positive_exact: int = 0,
    min_positive_consensus: int = 0,
    min_negative_generated: int = 0,
) -> None:
    counts = corpus.probe_counts
    if counts.get("positive_exact", 0) < min_positive_exact:
        raise ValueError("generated corpus does not contain enough positive_exact probes")
    if counts.get("positive_consensus", 0) < min_positive_consensus:
        raise ValueError("generated corpus does not contain enough positive_consensus probes")
    if counts.get("negative_generated", 0) < min_negative_generated:
        raise ValueError("generated corpus does not contain enough negative_generated probes")
    seen_ids: set[str] = set()
    for probe in corpus.probes:
        if probe.id in seen_ids:
            raise ValueError(f"duplicate probe id: {probe.id}")
        seen_ids.add(probe.id)
        _validate_probe_logic(probe)


def validate_probe_corpus(
    corpus: ProbeCorpus,
    *,
    min_positive_exact: int = 0,
    min_positive_consensus: int = 0,
    min_negative_generated: int = 0,
) -> dict[str, int]:
    validate_generated_probe_corpus(
        corpus,
        min_positive_exact=min_positive_exact,
        min_positive_consensus=min_positive_consensus,
        min_negative_generated=min_negative_generated,
    )
    if not corpus.probes:
        raise ValueError("generated corpus is empty")
    return dict(corpus.probe_counts)


def validate_probe_candidate(
    candidate: GeneratedProbeCandidate,
    config: ProbeCorpusConfig,
    client: BaselineResolverClient,
) -> GeneratedProbeValidation:
    if candidate.kind == "positive_exact":
        return validate_positive_exact_probe(candidate.probe, config, client)
    if candidate.kind == "positive_consensus":
        return validate_positive_consensus_probe(candidate.probe, config, client)
    if candidate.kind == "negative_generated":
        return validate_negative_parent_zone(
            parent_zone=candidate.probe.parent_zone or "",
            config=config,
            client=client,
        )
    return GeneratedProbeValidation(accepted=False, rejection_reason="unsupported_probe_kind")


def validate_positive_exact_probe(
    probe: ProbeDefinition,
    config: ProbeCorpusConfig,
    client: BaselineResolverClient,
) -> GeneratedProbeValidation:
    expected = normalize_expected_answers(probe.expected_answers, probe.qtype)
    results = asyncio.run(
        _collect_rrset_results(
            qname=probe.qname or "",
            qtype=probe.qtype,
            resolvers=config.baseline.resolvers,
            rounds=config.validation.exact.rounds,
            client=client,
        )
    )
    return _validate_exact_results(
        results,
        expected,
        probe.qtype,
        config.validation.exact.required_quorum,
    )


def validate_positive_consensus_probe(
    probe: ProbeDefinition,
    config: ProbeCorpusConfig,
    client: BaselineResolverClient,
) -> GeneratedProbeValidation:
    results = asyncio.run(
        _collect_rrset_results(
            qname=probe.qname or "",
            qtype=probe.qtype,
            resolvers=config.baseline.resolvers,
            rounds=config.validation.consensus.rounds,
            client=client,
        )
    )
    return _validate_consensus_results(results, config.validation.consensus.required_quorum)


def validate_negative_parent_zone(
    *,
    parent_zone: str,
    config: ProbeCorpusConfig,
    client: BaselineResolverClient,
) -> GeneratedProbeValidation:
    negative = config.validation.negative
    results = asyncio.run(
        _collect_negative_results(
            parent_zone=parent_zone,
            resolvers=config.baseline.resolvers,
            rounds=negative.rounds,
            labels_per_parent=negative.labels_per_parent,
            label_length=negative.label_length,
            client=client,
        )
    )
    return _validate_negative_results(results, negative.required_quorum)


async def _collect_rrset_results(
    *,
    qname: str,
    qtype: str,
    resolvers: list[str],
    rounds: int,
    client: BaselineResolverClient,
) -> list[BaselineQueryResult]:
    results: list[BaselineQueryResult] = []
    for _ in range(rounds):
        for resolver in resolvers:
            results.append(await client.query(resolver, qname, qtype))
    return results


async def _collect_negative_results(
    *,
    parent_zone: str,
    resolvers: list[str],
    rounds: int,
    labels_per_parent: int,
    label_length: int,
    client: BaselineResolverClient,
) -> list[list[BaselineQueryResult]]:
    checks: list[list[BaselineQueryResult]] = []
    for _ in range(rounds):
        for _ in range(labels_per_parent):
            qname = generate_negative_qname(parent_zone, label_length=label_length)
            check_results: list[BaselineQueryResult] = []
            for resolver in resolvers:
                check_results.append(await client.query(resolver, qname, "A"))
            checks.append(check_results)
    return checks


def _validate_exact_results(
    results: list[BaselineQueryResult],
    expected: list[str],
    qtype: str,
    required_quorum: int,
) -> GeneratedProbeValidation:
    matches = 0
    timeouts = 0
    mismatches: list[str] = []

    for result in results:
        if result.error:
            timeouts += 1
            continue
        if result.rcode != "NOERROR":
            mismatches.append(result.rcode)
            continue
        normalized_answers = normalize_expected_answers(result.answers, qtype)
        if normalized_answers != expected:
            mismatches.append(",".join(normalized_answers))
            continue
        matches += 1

    if mismatches:
        return GeneratedProbeValidation(
            accepted=False,
            rejection_reason="exact_rrset_mismatch",
            details={"expected": ",".join(expected), "observed": mismatches[0]},
        )
    if matches < required_quorum:
        reason = (
            "timeout_rate_high"
            if timeouts > len(results) / 2
            else "insufficient_baseline_consensus"
        )
        return GeneratedProbeValidation(accepted=False, rejection_reason=reason)
    return GeneratedProbeValidation(accepted=True, agreed_answers=expected)


def _validate_consensus_results(
    results: list[BaselineQueryResult],
    required_quorum: int,
) -> GeneratedProbeValidation:
    timeouts = sum(1 for result in results if result.error)
    successful = [result for result in results if not result.error and result.rcode == "NOERROR"]
    if not successful:
        return GeneratedProbeValidation(accepted=False, rejection_reason="timeout_rate_high")

    answer_counter = Counter(tuple(sorted(result.answers)) for result in successful)
    top_answers, top_count = answer_counter.most_common(1)[0]
    if top_count < required_quorum:
        return GeneratedProbeValidation(
            accepted=False,
            rejection_reason="insufficient_baseline_consensus",
        )
    if len(answer_counter) > 1:
        return GeneratedProbeValidation(
            accepted=False,
            rejection_reason="baseline_disagreement",
            details={"top_answers": ",".join(top_answers)},
        )
    if timeouts > len(results) / 2:
        return GeneratedProbeValidation(accepted=False, rejection_reason="timeout_rate_high")
    return GeneratedProbeValidation(
        accepted=True,
        agreed_nameservers=list(top_answers),
    )


def _validate_negative_results(
    checks: list[list[BaselineQueryResult]],
    required_quorum: int,
) -> GeneratedProbeValidation:
    for results in checks:
        nx_count = 0
        for result in results:
            if result.error:
                continue
            if result.rcode == "NXDOMAIN" and not result.answers:
                nx_count += 1
                continue
            if result.rcode == "NOERROR" or result.answers:
                return GeneratedProbeValidation(
                    accepted=False,
                    rejection_reason="negative_parent_wildcard_like",
                    details={"qname": result.qname, "rcode": result.rcode},
                )
            return GeneratedProbeValidation(
                accepted=False,
                rejection_reason="negative_parent_inconsistent",
                details={"qname": result.qname, "rcode": result.rcode},
            )
        if nx_count < required_quorum:
            return GeneratedProbeValidation(
                accepted=False,
                rejection_reason="insufficient_baseline_consensus",
            )
    return GeneratedProbeValidation(accepted=True)


def validate_generation_thresholds(
    report: ProbeGenerationReport,
    config: ProbeCorpusConfig,
) -> None:
    thresholds = config.thresholds
    if report.accepted_counts.get("positive_exact", 0) < thresholds.min_positive_exact:
        raise ValueError("accepted corpus fell below min_positive_exact threshold")
    if report.accepted_counts.get("positive_consensus", 0) < thresholds.min_positive_consensus:
        raise ValueError("accepted corpus fell below min_positive_consensus threshold")
    if report.accepted_counts.get("negative_generated", 0) < thresholds.min_negative_generated:
        raise ValueError("accepted corpus fell below min_negative_generated threshold")


def generate_negative_qname(parent_zone: str, *, label_length: int = 40) -> str:
    alphabet = string.ascii_lowercase + string.digits
    label = "".join(alphabet[b % len(alphabet)] for b in secrets.token_bytes(label_length))
    return f"{label[:label_length]}.{parent_zone.rstrip('.')}."


def _validate_probe_logic(probe: ProbeDefinition) -> None:
    if probe.kind == "positive_exact" and probe.expected_mode != "exact_rrset":
        raise ValueError("positive_exact probes must use expected_mode=exact_rrset")
    if probe.kind == "positive_consensus" and probe.expected_mode != "consensus_match":
        raise ValueError("positive_consensus probes must use expected_mode=consensus_match")
    if probe.kind == "negative_generated" and probe.expected_mode != "nxdomain":
        raise ValueError("negative_generated probes must use expected_mode=nxdomain")
    if probe.kind == "negative_generated" and not probe.parent_zone:
        raise ValueError("negative_generated probes must set parent_zone")


def _parse_resolver(endpoint: str) -> tuple[str, int]:
    if ":" in endpoint and endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        return host, int(port)
    return endpoint, 53
