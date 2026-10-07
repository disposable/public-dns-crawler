"""Unit tests for plain-DNS backend selection in validate pipeline."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate import _run_plain_dns_specs, validate_candidates_stream
from resolver_inventory.validate.corpus import CorpusEntry
from resolver_inventory.validate.massdns_backend import MassDnsSessionMetrics
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


def _pipeline_settings(backend: str) -> Settings:
    settings = Settings()
    settings.validation.dns_backend.kind = backend
    settings.validation.rounds = 1
    settings.validation.corpus.mode = "controlled"
    settings.validation.corpus.zone = "test.local"
    return settings


def _udp53_candidate() -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport="dns-udp",
        endpoint_url=None,
        host="192.0.2.55",
        port=53,
        path=None,
    )


def test_python_backend_executes_udp53_specs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the default python backend must run massdns-supported specs too."""
    settings = _pipeline_settings("python")
    executed: list[str] = []

    async def fake_python_runner(specs, **kwargs):
        for spec in specs:
            executed.append(spec.probe_id)
            await kwargs["on_execution"](
                PlainDnsProbeExecution(
                    spec=spec,
                    result=ProbeResult(ok=True, probe=spec.probe_name, latency_ms=1.0),
                )
            )
        return []

    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fake_python_runner,
    )

    results = []
    validate_candidates_stream([_udp53_candidate()], results.append, settings)

    # controlled corpus: A, AAAA, TXT, CNAME positives + 1 nxdomain probe
    assert len(executed) == 5
    assert len(results) == 1
    assert len(results[0].probes) == 5
    assert results[0].accepted is True


def test_massdns_backend_runs_session_per_supported_rdtype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MassDNS must get a session for every rdtype the corpus uses, not just A/AAAA/NS."""
    settings = _pipeline_settings("massdns")
    sessions: list[str] = []

    async def fake_session(
        specs_source,
        *,
        rdtype,
        config,
        timeout_s,
        baseline_resolvers,
        baseline_cache,
        on_execution=None,
    ):
        sessions.append(rdtype)
        for spec in specs_source():
            await on_execution(
                PlainDnsProbeExecution(
                    spec=spec,
                    result=ProbeResult(ok=True, probe=spec.probe_name, latency_ms=1.0),
                )
            )
        return [], MassDnsSessionMetrics(exit_code=0)

    async def fail_python_runner(specs, **kwargs):
        raise AssertionError("python runner should not be used for udp:53 specs")

    monkeypatch.setattr(
        "resolver_inventory.validate.run_massdns_rdtype_session",
        fake_session,
    )
    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fail_python_runner,
    )

    results = []
    validate_candidates_stream([_udp53_candidate()], results.append, settings)

    assert sessions == ["A", "AAAA", "CNAME", "TXT"]
    assert len(results) == 1
    assert len(results[0].probes) == 5


def test_massdns_session_crash_falls_back_to_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crashing massdns session must fall back to the python runner, not drop probes."""
    settings = _pipeline_settings("massdns")
    settings.validation.dns_backend.fallback_to_python_on_error = True
    executed: list[str] = []

    async def fake_session(*args, **kwargs):
        raise OSError("spawn failed")

    async def fake_python_runner(specs, **kwargs):
        for spec in specs:
            executed.append(spec.probe_id)
            await kwargs["on_execution"](
                PlainDnsProbeExecution(
                    spec=spec,
                    result=ProbeResult(ok=True, probe=spec.probe_name, latency_ms=1.0),
                )
            )
        return []

    monkeypatch.setattr(
        "resolver_inventory.validate.run_massdns_rdtype_session",
        fake_session,
    )
    monkeypatch.setattr(
        "resolver_inventory.validate.run_python_plain_dns_batch",
        fake_python_runner,
    )

    results = []
    validate_candidates_stream([_udp53_candidate()], results.append, settings)

    assert len(executed) == 5
    assert len(results) == 1
    assert results[0].accepted is True


def test_massdns_session_crash_propagates_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _pipeline_settings("massdns")
    settings.validation.dns_backend.fallback_to_python_on_error = False

    async def fake_session(*args, **kwargs):
        raise OSError("spawn failed")

    monkeypatch.setattr(
        "resolver_inventory.validate.run_massdns_rdtype_session",
        fake_session,
    )

    with pytest.raises(OSError, match="spawn failed"):
        validate_candidates_stream([_udp53_candidate()], lambda r: None, settings)
