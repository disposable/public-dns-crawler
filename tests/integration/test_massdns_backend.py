"""Integration tests for MassDNS backend using a fake executable."""

from __future__ import annotations

from pathlib import Path

import pytest

from resolver_inventory.settings import DnsBackendConfig
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.massdns_backend import run_massdns_batch
from resolver_inventory.validate.plain_dns_backend import PlainDnsProbeSpec

pytestmark = pytest.mark.integration


def _make_fake_massdns(tmp_path: Path) -> Path:
    script = tmp_path / "fake_massdns.py"
    script.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import json, os, sys",
                'mode = os.environ.get("FAKE_MASSDNS_MODE", "success")',
                "for line_no, line in enumerate(sys.stdin, start=1):",
                "    parts = line.strip().split()",
                "    if len(parts) < 2:",
                "        continue",
                "    qname, resolver = parts[0], parts[1]",
                '    rdtype = os.environ.get("FAKE_MASSDNS_RDTYPE", "A")',
                "    if mode == 'malformed' and line_no == 1:",
                "        sys.stdout.write('{bad json}\\n')",
                "        sys.stdout.flush()",
                "        continue",
                "    if mode == 'partial-crash' and line_no > 1:",
                "        sys.exit(3)",
                "    if mode == 'stall':",
                "        import time",
                "        time.sleep(5)",
                "        continue",
                "    payload = {",
                "        'name': qname,",
                "        'resolver': resolver,",
                "        'type': rdtype,",
                "        'status': 'NOERROR',",
                "        'answers': [{'type': rdtype, 'data': '192.0.2.1'}],",
                "    }",
                "    if mode == 'terminal-failure' and line_no % 2 == 0:",
                "        payload = {",
                "            'name': qname,",
                "            'resolver': resolver,",
                "            'type': rdtype,",
                "            'error': 'timeout',",
                "        }",
                "    sys.stderr.write('warn line\\n')",
                "    sys.stderr.flush()",
                "    sys.stdout.write(json.dumps(payload) + '\\n')",
                "    sys.stdout.flush()",
            ]
        ),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _spec(probe_id: str) -> PlainDnsProbeSpec:
    entry = CorpusEntry(
        qname="a.ok.test.local.",
        rdtype="A",
        expected_mode="exact_rrset",
        expected_answers=["192.0.2.1"],
        label=probe_id,
    )
    return PlainDnsProbeSpec(
        probe_id=probe_id,
        kind="positive",
        candidate_idx=0,
        candidate_transport="dns-udp",
        host="127.0.0.1",
        port=53,
        qname="a.ok.test.local.",
        rdtype="A",
        probe_name=f"dns-udp:positive:{probe_id}",
        is_nxdomain_probe=False,
        expected_answers=["192.0.2.1"],
        baseline_key=None,
        entry=entry,
    )


@pytest.mark.asyncio
async def test_massdns_all_success_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _make_fake_massdns(tmp_path)
    monkeypatch.setenv("FAKE_MASSDNS_MODE", "success")
    cfg = DnsBackendConfig(kind="massdns", massdns_bin=str(fake))
    results, metrics = await run_massdns_batch(
        [_spec("p1"), _spec("p2")],
        config=cfg,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert len(results) == 2
    assert all(item.result.ok for item in results)
    assert metrics.parsed_results == 2
    assert metrics.stderr_lines >= 1


@pytest.mark.asyncio
async def test_massdns_terminal_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _make_fake_massdns(tmp_path)
    monkeypatch.setenv("FAKE_MASSDNS_MODE", "terminal-failure")
    cfg = DnsBackendConfig(kind="massdns", massdns_bin=str(fake))
    results, _ = await run_massdns_batch(
        [_spec("p1"), _spec("p2")],
        config=cfg,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert len(results) == 2
    assert any(
        (not item.result.ok and item.result.error and "timeout_or_error" in item.result.error)
        for item in results
    )


@pytest.mark.asyncio
async def test_massdns_malformed_ndjson_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _make_fake_massdns(tmp_path)
    monkeypatch.setenv("FAKE_MASSDNS_MODE", "malformed")
    cfg = DnsBackendConfig(kind="massdns", massdns_bin=str(fake))
    with pytest.raises(ValueError):
        await run_massdns_batch(
            [_spec("p1")],
            config=cfg,
            timeout_s=1.0,
            baseline_resolvers=["127.0.0.1:53"],
            baseline_cache={},
        )


@pytest.mark.asyncio
async def test_massdns_crash_after_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _make_fake_massdns(tmp_path)
    monkeypatch.setenv("FAKE_MASSDNS_MODE", "partial-crash")
    cfg = DnsBackendConfig(kind="massdns", massdns_bin=str(fake))
    results, metrics = await run_massdns_batch(
        [_spec("p1"), _spec("p2")],
        config=cfg,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert len(results) == 2
    assert metrics.exit_code != 0
    assert any(item.result.ok for item in results)
    assert any(
        (
            not item.result.ok
            and item.result.error
            and (
                "massdns_unmatched" in item.result.error or "timeout_or_error" in item.result.error
            )
        )
        for item in results
    )


@pytest.mark.asyncio
async def test_massdns_stalled_stdout_times_out(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _make_fake_massdns(tmp_path)
    monkeypatch.setenv("FAKE_MASSDNS_MODE", "stall")
    cfg = DnsBackendConfig(kind="massdns", massdns_bin=str(fake))
    with pytest.raises(TimeoutError, match="batch timed out"):
        await run_massdns_batch(
            [_spec("p1")],
            config=cfg,
            timeout_s=0.05,
            baseline_resolvers=["127.0.0.1:53"],
            baseline_cache={},
        )
