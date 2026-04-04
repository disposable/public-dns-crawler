"""Unit tests for data models."""

from __future__ import annotations

from resolver_inventory.models import Candidate, ProbeResult, ValidationResult


def _make_dns_candidate(**kwargs: object) -> Candidate:
    defaults: dict[str, object] = {
        "provider": "TestProvider",
        "source": "manual-dns",
        "transport": "dns-udp",
        "endpoint_url": None,
        "host": "192.0.2.1",
        "port": 53,
        "path": None,
    }
    defaults.update(kwargs)
    return Candidate(**defaults)  # type: ignore[arg-type]


def _make_doh_candidate(**kwargs: object) -> Candidate:
    defaults: dict[str, object] = {
        "provider": "TestDoH",
        "source": "manual-doh",
        "transport": "doh",
        "endpoint_url": "https://dns.example.com/dns-query",
        "host": "dns.example.com",
        "port": 443,
        "path": "/dns-query",
        "tls_server_name": "dns.example.com",
    }
    defaults.update(kwargs)
    return Candidate(**defaults)  # type: ignore[arg-type]


class TestCandidate:
    def test_str_dns_udp(self) -> None:
        c = _make_dns_candidate()
        assert str(c) == "dns-udp:192.0.2.1:53"

    def test_str_doh(self) -> None:
        c = _make_doh_candidate()
        assert str(c) == "doh:https://dns.example.com/dns-query"

    def test_default_bootstrap_lists(self) -> None:
        c = _make_dns_candidate()
        assert c.bootstrap_ipv4 == []
        assert c.bootstrap_ipv6 == []

    def test_default_metadata(self) -> None:
        c = _make_dns_candidate()
        assert c.metadata == {}

    def test_slots(self) -> None:
        c = _make_dns_candidate()
        assert not hasattr(c, "__dict__")


class TestProbeResult:
    def test_ok_probe(self) -> None:
        p = ProbeResult(ok=True, probe="udp:positive:test", latency_ms=12.5)
        assert p.ok
        assert p.latency_ms == 12.5
        assert p.error is None

    def test_fail_probe(self) -> None:
        p = ProbeResult(ok=False, probe="udp:nxdomain:test", error="timeout")
        assert not p.ok
        assert p.error == "timeout"

    def test_slots(self) -> None:
        p = ProbeResult(ok=True, probe="x")
        assert not hasattr(p, "__dict__")


class TestValidationResult:
    def _make_result(self, probes: list[ProbeResult]) -> ValidationResult:
        return ValidationResult(
            candidate=_make_dns_candidate(),
            accepted=True,
            score=90,
            status="accepted",
            reasons=[],
            probes=probes,
        )

    def test_median_latency_no_probes(self) -> None:
        r = self._make_result([])
        assert r.median_latency_ms() is None

    def test_median_latency_single(self) -> None:
        p = ProbeResult(ok=True, probe="x", latency_ms=100.0)
        r = self._make_result([p])
        assert r.median_latency_ms() == 100.0

    def test_median_latency_even(self) -> None:
        probes = [
            ProbeResult(ok=True, probe="x", latency_ms=10.0),
            ProbeResult(ok=True, probe="y", latency_ms=20.0),
        ]
        r = self._make_result(probes)
        assert r.median_latency_ms() == 15.0

    def test_median_latency_odd(self) -> None:
        probes = [
            ProbeResult(ok=True, probe="a", latency_ms=10.0),
            ProbeResult(ok=True, probe="b", latency_ms=30.0),
            ProbeResult(ok=True, probe="c", latency_ms=20.0),
        ]
        r = self._make_result(probes)
        assert r.median_latency_ms() == 20.0

    def test_median_latency_skips_failures(self) -> None:
        probes = [
            ProbeResult(ok=True, probe="a", latency_ms=50.0),
            ProbeResult(ok=False, probe="b", error="timeout"),
        ]
        r = self._make_result(probes)
        assert r.median_latency_ms() == 50.0
