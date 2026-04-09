"""Unit tests for plain-DNS backend selection in validate pipeline."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from resolver_inventory.models import ProbeResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate import _run_plain_dns_specs
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.plain_dns_backend import PlainDnsProbeExecution, PlainDnsProbeSpec


def _spec(
    probe_id: str,
    *,
    transport: str = "dns-udp",
    port: int = 53,
) -> PlainDnsProbeSpec:
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
        candidate_transport=transport,
        host="127.0.0.1",
        port=port,
        qname="a.ok.test.local.",
        rdtype="A",
        probe_name=f"{transport}:positive:{probe_id}",
        is_nxdomain_probe=False,
        expected_answers=["192.0.2.1"],
        baseline_key=None,
        entry=entry,
    )


@pytest.mark.asyncio
async def test_backend_python_uses_python_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.validation.dns_backend.kind = "python"
    calls = {"python": 0}

    async def fake_python_runner(*args, **kwargs):
        calls["python"] += 1
        return []

    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fake_python_runner,
    )

    await _run_plain_dns_specs(
        [_spec("p1")],
        settings,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert calls["python"] == 1


@pytest.mark.asyncio
async def test_backend_massdns_falls_back_for_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.validation.dns_backend.kind = "massdns"
    seen: list[str] = []

    async def fake_python_runner(specs, **kwargs):
        seen.extend(spec.probe_id for spec in specs)
        return []

    async def fake_massdns_runner(*args, **kwargs):
        return [], SimpleNamespace(
            parsed_results=0,
            stdout_lines=0,
            stderr_lines=0,
            unmatched_results=0,
            exit_code=0,
        )

    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fake_python_runner,
    )
    monkeypatch.setattr("resolver_inventory.validate.run_massdns_batch", fake_massdns_runner)

    await _run_plain_dns_specs(
        [
            _spec("udp53", transport="dns-udp", port=53),
            _spec("tcp53", transport="dns-tcp", port=53),
            _spec("udp5353", transport="dns-udp", port=5353),
        ],
        settings,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert "tcp53" in seen
    assert "udp5353" in seen


@pytest.mark.asyncio
async def test_backend_massdns_error_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings()
    settings.validation.dns_backend.kind = "massdns"
    settings.validation.dns_backend.fallback_to_python_on_error = True
    fallback_calls = {"python": 0}

    async def fake_python_runner(specs, **kwargs):
        fallback_calls["python"] += len(specs)
        return [
            PlainDnsProbeExecution(
                spec=spec,
                result=ProbeResult(
                    ok=True,
                    probe=spec.probe_name,
                    latency_ms=1.0,
                    error=None,
                    details={},
                ),
            )
            for spec in specs
        ]

    async def fake_massdns_runner(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fake_python_runner,
    )
    monkeypatch.setattr("resolver_inventory.validate.run_massdns_batch", fake_massdns_runner)

    specs = [_spec("udp53", transport="dns-udp", port=53)]
    out = await _run_plain_dns_specs(
        specs,
        settings,
        timeout_s=1.0,
        baseline_resolvers=["127.0.0.1:53"],
        baseline_cache={},
    )
    assert len(out) == 1
    assert fallback_calls["python"] == 1
