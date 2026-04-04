"""Unit tests for runtime expected_mode enforcement."""

from __future__ import annotations

import dns.message
import dns.rrset
import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.validate.corpus import Corpus, CorpusEntry
from resolver_inventory.validate.dns_plain import _probe_positive, validate_dns_candidate


def _response(qname: str, rdtype: str, *answers: str) -> dns.message.Message:
    msg = dns.message.make_response(dns.message.make_query(qname, rdtype))
    if answers:
        msg.answer.append(dns.rrset.from_text(qname, 60, "IN", rdtype, *answers))
    return msg


@pytest.mark.asyncio
async def test_exact_rrset_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_query_udp(*args: object, **kwargs: object) -> tuple[dns.message.Message, float]:
        return _response("a.ok.test.local.", "A", "10.0.0.1"), 1.0

    monkeypatch.setattr("resolver_inventory.validate.dns_plain._query_udp", fake_query_udp)

    result = await _probe_positive(
        CorpusEntry(
            qname="a.ok.test.local.",
            rdtype="A",
            expected_mode="exact_rrset",
            expected_answers=["192.0.2.1"],
            label="exact-a",
        ),
        "127.0.0.1",
        53,
        "dns-udp",
        1.0,
        ["127.0.0.1:53"],
        {},
    )

    assert not result.ok
    assert result.error == "answer_mismatch"


@pytest.mark.asyncio
async def test_consensus_ns_comparison(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_query_udp(*args: object, **kwargs: object) -> tuple[dns.message.Message, float]:
        return _response("test.local.", "NS", "evil.test.local."), 1.0

    async def fake_baseline(*args: object, **kwargs: object) -> list[str]:
        return ["ns.test.local."]

    monkeypatch.setattr("resolver_inventory.validate.dns_plain._query_udp", fake_query_udp)
    monkeypatch.setattr(
        "resolver_inventory.validate.dns_plain.resolve_baseline_answers",
        fake_baseline,
    )

    result = await _probe_positive(
        CorpusEntry(
            qname="test.local.",
            rdtype="NS",
            expected_mode="consensus_match",
            label="consensus-ns",
        ),
        "127.0.0.1",
        53,
        "dns-udp",
        1.0,
        ["127.0.0.1:53"],
        {},
    )

    assert not result.ok
    assert result.error == "answer_mismatch"


@pytest.mark.asyncio
async def test_negative_generated_expands_at_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_qnames: list[str] = []
    labels = iter(["firstlabel", "secondlabel"])

    async def fake_query_udp(
        host: str,
        port: int,
        msg: dns.message.Message,
        timeout_s: float,
    ) -> tuple[dns.message.Message, float]:
        seen_qnames.append(msg.question[0].name.to_text())
        response = dns.message.make_response(msg)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response, 1.0

    monkeypatch.setattr("resolver_inventory.validate.dns_plain._query_udp", fake_query_udp)
    monkeypatch.setattr(
        "resolver_inventory.validate.corpus._random_label",
        lambda label_length: next(labels),
    )

    candidate = Candidate(
        provider=None,
        source="test",
        transport="dns-udp",
        endpoint_url=None,
        host="127.0.0.1",
        port=53,
        path=None,
    )
    corpus = Corpus(
        nxdomain=[
            CorpusEntry(
                qname_template="{uuid}.test.local.",
                rdtype="A",
                expected_mode="nxdomain",
                parent_zone="test.local.",
                nxdomain=True,
                label="neg-runtime",
            )
        ]
    )

    await validate_dns_candidate(candidate, corpus, rounds=2, timeout_s=1.0)

    assert seen_qnames == ["firstlabel.test.local.", "secondlabel.test.local."]
