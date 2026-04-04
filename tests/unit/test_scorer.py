"""Unit tests for the scoring engine."""

from __future__ import annotations

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate.scorer import score


def _candidate(transport: str = "dns-udp") -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport=transport,  # type: ignore[arg-type]
        endpoint_url=None if transport != "doh" else "https://dns.example.com/dns-query",
        host="192.0.2.1" if transport != "doh" else "dns.example.com",
        port=53 if transport != "doh" else 443,
        path=None if transport != "doh" else "/dns-query",
    )


def _ok(probe: str = "dns-udp:positive:test", ms: float = 10.0) -> ProbeResult:
    return ProbeResult(ok=True, probe=probe, latency_ms=ms)


def _fail(probe: str = "dns-udp:positive:test", error: str = "timeout_or_error:x") -> ProbeResult:
    return ProbeResult(ok=False, probe=probe, error=error)


class TestScorer:
    def test_all_passing_is_accepted(self) -> None:
        probes = [_ok() for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert result.status == "accepted"
        assert result.accepted is True
        assert result.score >= 80

    def test_no_probes_is_rejected(self) -> None:
        result = score(_candidate(), [], Settings())
        assert result.status == "rejected"
        assert result.score == 0
        assert "no_probes" in result.reasons

    def test_nxdomain_spoofing_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="nxdomain_spoofing")]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"
        assert "nxdomain_spoofing" in result.reasons

    def test_tls_mismatch_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="tls_name_mismatch:cert err")]
        result = score(_candidate("doh"), probes, Settings())
        assert result.status == "rejected"
        assert "tls_name_mismatch" in result.reasons

    def test_all_timeouts_rejected(self) -> None:
        probes = [_fail(error="timeout_or_error:timed out") for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"

    def test_high_timeout_rate_flagged(self) -> None:
        probes = [_fail(error="timeout_or_error:x") for _ in range(8)] + [_ok(), _ok()]
        result = score(_candidate(), probes, Settings())
        assert "timeout_rate_high" in result.reasons

    def test_custom_thresholds(self) -> None:
        settings = Settings()
        settings.scoring.accept_min_score = 50
        settings.scoring.candidate_min_score = 30
        probes = [_ok() for _ in range(6)] + [_fail() for _ in range(4)]
        result = score(_candidate(), probes, settings)
        assert result.score >= 0

    def test_score_bounded_0_100(self) -> None:
        probes = [_fail(error="nxdomain_spoofing") for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert 0 <= result.score <= 100

    def test_latency_p95_high_flagged(self) -> None:
        probes = [_ok(ms=3000.0) for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert "latency_p95_high" in result.reasons
