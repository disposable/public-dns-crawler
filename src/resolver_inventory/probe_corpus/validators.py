"""Logical and baseline-backed validation for probe corpora."""

from __future__ import annotations

import asyncio
import secrets
import string

import dns.asyncquery
import dns.message
import dns.rdatatype

from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition


def validate_generated_probe_corpus(
    corpus: ProbeCorpus,
    *,
    min_exact_probes: int = 0,
    min_consensus_probes: int = 0,
    min_negative_parents: int = 0,
) -> None:
    counts = corpus.probe_counts
    if counts.get("positive_exact", 0) < min_exact_probes:
        raise ValueError("generated corpus does not contain enough positive_exact probes")
    if counts.get("positive_consensus", 0) < min_consensus_probes:
        raise ValueError("generated corpus does not contain enough positive_consensus probes")
    if counts.get("negative_generated", 0) < min_negative_parents:
        raise ValueError("generated corpus does not contain enough negative_generated probes")

    seen_ids: set[str] = set()
    for probe in corpus.probes:
        if probe.id in seen_ids:
            raise ValueError(f"duplicate probe id: {probe.id}")
        seen_ids.add(probe.id)
        _validate_probe_logic(probe)


def validate_probe_corpus(corpus: ProbeCorpus) -> dict[str, int]:
    validate_generated_probe_corpus(corpus)
    return dict(corpus.probe_counts)


def _validate_probe_logic(probe: ProbeDefinition) -> None:
    if probe.kind == "positive_exact" and probe.expected_mode != "exact_rrset":
        raise ValueError("positive_exact probes must use expected_mode=exact_rrset")
    if probe.kind == "positive_consensus" and probe.expected_mode != "consensus_match":
        raise ValueError("positive_consensus probes must use expected_mode=consensus_match")
    if probe.kind == "negative_generated" and probe.expected_mode != "nxdomain":
        raise ValueError("negative_generated probes must use expected_mode=nxdomain")
    if probe.kind == "negative_generated" and not probe.parent_zone:
        raise ValueError("negative_generated probes must set parent_zone")


def validate_negative_parent_zone(
    *,
    parent_zone: str,
    resolvers: list[str],
    label_length: int = 40,
    validation_rounds: int = 3,
    query_fn=None,
) -> bool:
    async def runner() -> bool:
        actual_query = query_fn or _query_resolver
        for _ in range(validation_rounds):
            qname = generate_negative_qname(parent_zone, label_length=label_length)
            for resolver in resolvers:
                rcode = await actual_query(resolver, qname)
                if rcode != "NXDOMAIN":
                    return False
        return True

    return asyncio.run(runner())


def generate_negative_qname(parent_zone: str, *, label_length: int = 40) -> str:
    alphabet = string.ascii_lowercase + string.digits
    label = "".join(alphabet[b % len(alphabet)] for b in secrets.token_bytes(label_length))
    return f"{label[:label_length]}.{parent_zone.rstrip('.')}."


async def _query_resolver(resolver: str, qname: str) -> str:
    host, port = _parse_resolver(resolver)
    msg = dns.message.make_query(qname, dns.rdatatype.A)
    msg.id = 0
    response = await dns.asyncquery.udp(msg, host, port=port, timeout=2.0)
    return dns.rcode.to_text(response.rcode())  # type: ignore[attr-defined]


def _parse_resolver(endpoint: str) -> tuple[str, int]:
    if ":" in endpoint and endpoint.count(":") == 1:
        host, port = endpoint.rsplit(":", 1)
        return host, int(port)
    return endpoint, 53
