"""Unit tests for MassDNS backend helpers."""

from __future__ import annotations

import asyncio

import pytest

from resolver_inventory.settings import DnsBackendConfig
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.massdns_backend import (
    MassDnsParsedResult,
    build_manifest_line,
    build_massdns_command,
    group_probe_specs_for_massdns,
    normalize_massdns_result,
    parse_massdns_ndjson_line,
    parse_massdns_ndjson_stream,
)
from resolver_inventory.validate.plain_dns_backend import PlainDnsProbeSpec


def _spec(
    *,
    probe_id: str,
    rdtype: str = "A",
    transport: str = "dns-udp",
    port: int = 53,
) -> PlainDnsProbeSpec:
    entry = CorpusEntry(
        qname="a.ok.test.local.",
        rdtype=rdtype,
        expected_mode="exact_rrset",
        expected_answers=["192.0.2.1"] if rdtype == "A" else [],
        label=f"probe-{probe_id}",
    )
    return PlainDnsProbeSpec(
        probe_id=probe_id,
        kind="positive",
        candidate_idx=0,
        candidate_transport=transport,
        host="127.0.0.1",
        port=port,
        qname="a.ok.test.local.",
        rdtype=rdtype,
        probe_name=f"{transport}:positive:{entry.label}",
        is_nxdomain_probe=False,
        expected_answers=list(entry.expected_answers),
        baseline_key=None,
        entry=entry,
    )


def test_group_probe_specs_for_massdns_by_rdtype_and_size() -> None:
    specs = [
        _spec(probe_id="1", rdtype="A"),
        _spec(probe_id="2", rdtype="AAAA"),
        _spec(probe_id="3", rdtype="A"),
    ]
    batches = group_probe_specs_for_massdns(specs, batch_max_queries=1)
    assert len(batches) == 3
    assert [batch[0].rdtype for batch in batches] == ["A", "A", "AAAA"]


def test_build_manifest_line() -> None:
    line = build_manifest_line(_spec(probe_id="1", rdtype="A"))
    assert line == "a.ok.test.local. A 127.0.0.1:53\n"


def test_build_massdns_command() -> None:
    cfg = DnsBackendConfig(kind="massdns", massdns_bin="/usr/bin/massdns")
    cmd = build_massdns_command(config=cfg, rdtype="A", resolver_file="/tmp/r.txt")  # type: ignore[arg-type]
    assert cmd[0] == "/usr/bin/massdns"
    assert "--extended-input" in cmd
    assert "-o" in cmd and "Je" in cmd
    assert "-t" in cmd and "A" in cmd


def test_parse_massdns_ndjson_success_line() -> None:
    parsed = parse_massdns_ndjson_line(
        '{"name":"a.ok.test.local.","resolver":"127.0.0.1:53","type":"A",'
        '"status":"NOERROR","answers":[{"type":"A","data":"192.0.2.1"}]}'
    )
    assert parsed.qname == "a.ok.test.local."
    assert parsed.rcode == "NOERROR"
    assert parsed.answers == ["192.0.2.1"]


def test_parse_massdns_ndjson_terminal_failure_line() -> None:
    parsed = parse_massdns_ndjson_line(
        '{"name":"a.ok.test.local.","resolver":"127.0.0.1:53","type":"A","error":"timeout"}'
    )
    assert parsed.terminal_error == "timeout"


@pytest.mark.asyncio
async def test_parse_ndjson_stream_duplicate_key_matching() -> None:
    spec1 = _spec(probe_id="1")
    spec2 = _spec(probe_id="2")
    pending = {("127.0.0.1", "53", "a.ok.test.local.A"): [spec1, spec2]}
    stream = asyncio.StreamReader()
    stream.feed_data(
        b'{"name":"a.ok.test.local.","resolver":"127.0.0.1:53","type":"A","status":"NOERROR"}\n'
    )
    stream.feed_data(
        b'{"name":"a.ok.test.local.","resolver":"127.0.0.1:53","type":"A","status":"NOERROR"}\n'
    )
    stream.feed_eof()
    matched, unmatched, _ = await parse_massdns_ndjson_stream(stream, pending)
    assert unmatched == 0
    assert [spec.probe_id for spec, _ in matched] == ["1", "2"]


@pytest.mark.asyncio
async def test_normalize_massdns_result_positive() -> None:
    spec = _spec(probe_id="1")
    parsed = MassDnsParsedResult(
        resolver="127.0.0.1:53",
        qname="a.ok.test.local.",
        rdtype="A",
        rcode="NOERROR",
        answers=["192.0.2.1"],
        latency_ms=1.0,
    )
    result = await normalize_massdns_result(
        spec,
        parsed,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert result.ok is True
    assert result.probe == spec.probe_name
