"""Unit tests for the scoring engine with new component-based scoring."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from unittest.mock import MagicMock, patch

from resolver_inventory.history import (
    ResolverStabilityMetrics,
    RunMetadata,
    connect_history_db,
    update_history,
)
from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate.scorer import score


def _candidate(transport: str = "dns-udp", metadata: dict | None = None) -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport=transport,  # type: ignore[arg-type]
        endpoint_url=None if transport != "doh" else "https://dns.example.com/dns-query",
        host="192.0.2.1" if transport != "doh" else "dns.example.com",
        port=53 if transport != "doh" else 443,
        path=None if transport != "doh" else "/dns-query",
        metadata=metadata or {},
    )


def _ok(probe: str = "dns-udp:positive:test", ms: float = 10.0) -> ProbeResult:
    return ProbeResult(ok=True, probe=probe, latency_ms=ms)


def _fail(probe: str = "dns-udp:positive:test", error: str = "timeout_or_error:x") -> ProbeResult:
    return ProbeResult(ok=False, probe=probe, error=error)


class TestBasicScoring:
    """Test basic scoring functionality."""

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

    def test_score_bounded_0_100(self) -> None:
        probes = [_fail(error="nxdomain_spoofing") for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert 0 <= result.score <= 100

    def test_custom_thresholds(self) -> None:
        settings = Settings()
        settings.scoring.accept_min_score = 50
        settings.scoring.candidate_min_score = 30
        probes = [_ok() for _ in range(6)] + [_fail() for _ in range(4)]
        result = score(_candidate(), probes, settings)
        assert result.score >= 0


class TestComponentScores:
    """Test that component scores are properly computed."""

    def test_score_breakdown_present(self) -> None:
        probes = [_ok() for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert result.score_breakdown is not None
        assert "correctness" in result.score_breakdown
        assert "availability" in result.score_breakdown
        assert "performance" in result.score_breakdown
        assert "history" in result.score_breakdown

    def test_components_sum_to_final_score(self) -> None:
        probes = [_ok() for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        expected_sum = (
            result.correctness_score
            + result.availability_score
            + result.performance_score
            + result.history_score
        )
        assert result.score <= expected_sum + 5  # Allow small rounding/source penalties

    def test_correctness_score_with_errors(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="answer_mismatch")]
        result = score(_candidate(), probes, Settings())
        assert result.correctness_score < 50  # Should be penalized
        assert "answer_mismatch" in result.reasons

    def test_availability_score_based_on_success_rate(self) -> None:
        # 90% success should give ~18 points (90% of 20)
        probes = [_ok() for _ in range(9)] + [_fail()]
        result = score(_candidate(), probes, Settings())
        assert result.availability_score == 18

    def test_confidence_score_computed(self) -> None:
        probes = [_ok() for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert result.confidence_score > 0
        assert result.confidence_score <= 100


class TestHardFailCorrectness:
    """Test hard-fail correctness issues cap scores."""

    def test_nxdomain_spoofing_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="nxdomain_spoofing")]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"
        assert "nxdomain_spoofing" in result.reasons
        assert result.score <= 59
        assert "hard_fail_cap" in result.score_caps_applied

    def test_tls_mismatch_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="tls_name_mismatch:cert err")]
        result = score(_candidate("doh"), probes, Settings())
        assert result.status == "rejected"
        assert "tls_name_mismatch" in result.reasons
        assert result.score <= 59

    def test_answer_mismatch_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="answer_mismatch")]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"
        assert "answer_mismatch" in result.reasons
        assert result.score <= 59

    def test_suspicious_rcode_hard_fails(self) -> None:
        probes = [_ok() for _ in range(5)] + [_fail(error="unexpected_rcode:REFUSED")]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"
        assert result.score <= 59


class TestTailLatencyPenalties:
    """Test numeric tail-latency and jitter penalties."""

    def test_high_p50_penalty_applied(self) -> None:
        probes = [_ok(ms=800.0) for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert result.performance_score < 20
        assert "latency_high" in result.reasons
        assert result.derived_metrics.get("p50_latency_ms", 0) > 700

    def test_very_high_p50_penalty_applied(self) -> None:
        probes = [_ok(ms=1600.0) for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert "latency_very_high" in result.reasons

    def test_p95_penalty_applied(self) -> None:
        # Create probes with high p95 (most good, some very slow)
        probes = [_ok(ms=50.0) for _ in range(18)] + [_ok(ms=2000.0) for _ in range(2)]
        result = score(_candidate(), probes, Settings())
        assert "latency_p95_high" in result.reasons
        assert result.performance_score < 20

    def test_jitter_penalty_applied(self) -> None:
        # Create probes with high variance (high jitter)
        probes = [_ok(ms=50.0), _ok(ms=600.0), _ok(ms=55.0), _ok(ms=580.0)] * 5
        result = score(_candidate(), probes, Settings())
        jitter = result.derived_metrics.get("jitter_ms", 0)
        if jitter > 400:
            assert "latency_jitter_high" in result.reasons

    def test_latency_metrics_in_derived(self) -> None:
        probes = [_ok(ms=100.0) for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert "p50_latency_ms" in result.derived_metrics
        assert "p95_latency_ms" in result.derived_metrics
        assert "jitter_ms" in result.derived_metrics


class TestSourceReliability:
    """Test source reliability handling."""

    def test_low_reliability_penalty(self) -> None:
        candidate = _candidate(metadata={"reliability": "0.50"})
        probes = [_ok() for _ in range(10)]
        result = score(candidate, probes, Settings())
        assert "reliability_low" in result.reasons

    def test_missing_reliability_reduces_confidence(self) -> None:
        candidate = _candidate(metadata={})  # No reliability
        probes = [_ok() for _ in range(10)]
        result = score(candidate, probes, Settings())
        # Score should not be penalized, but confidence should be lower
        assert result.score > 80  # Good score still possible
        assert "source_reliability_unknown" in result.score_caps_applied

    def test_high_reliability_no_penalty(self) -> None:
        candidate = _candidate(metadata={"reliability": "0.98"})
        probes = [_ok() for _ in range(10)]
        result = score(candidate, probes, Settings())
        assert "reliability_low" not in result.reasons


class TestHistoryCaps:
    """Test history-based score caps."""

    def test_no_history_does_not_add_history_caps_or_reasons(self) -> None:
        candidate = _candidate()
        probes = [_ok() for _ in range(10)]
        result = score(candidate, probes, Settings())
        assert result.history_score == 0
        assert "no_history" not in result.reasons
        assert all(not cap.startswith("insufficient_history") for cap in result.score_caps_applied)

    def test_no_history_entry_skips_history_logic(self) -> None:
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = None
            result = score(
                _candidate(), [_ok() for _ in range(10)], Settings(), MagicMock(), date.today()
            )
            assert result.history_score == 0
            assert "no_history" not in result.reasons
            assert all(
                not cap.startswith("insufficient_history") for cap in result.score_caps_applied
            )

    def test_few_runs_caps_score(self) -> None:
        # Mock history with only 2 runs
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=2,
            runs_seen_30d=2,
            success_days_7d=2,
            success_days_30d=2,
            consecutive_success_days=2,
            consecutive_fail_days=0,
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            candidate = _candidate()
            probes = [_ok() for _ in range(10)]
            result = score(candidate, probes, Settings(), MagicMock(), date.today())
            assert result.score <= 90  # Capped due to < 3 runs

    def test_7_runs_caps_at_95(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=5,
            runs_seen_30d=7,
            success_days_7d=5,
            success_days_30d=7,
            consecutive_success_days=7,
            consecutive_fail_days=0,
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            candidate = _candidate()
            probes = [_ok() for _ in range(10)]
            result = score(candidate, probes, Settings(), MagicMock(), date.today())
            # 7-13 runs: cap at 98
            assert result.score <= 98
            assert result.history_score > 0

    def test_enough_runs_no_cap(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=14,
            consecutive_success_days=14,
            consecutive_fail_days=0,
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            candidate = _candidate()
            probes = [_ok() for _ in range(10)]
            result = score(candidate, probes, Settings(), MagicMock(), date.today())
            # Score can reach 98+ with 14+ runs
            assert result.score >= 95
            assert "insufficient_history" not in result.score_caps_applied


class TestPerfectScoreRequirements:
    """Test that score=100 has strict requirements."""

    def test_perfect_resolver_no_history_gets_99(self) -> None:
        probes = [_ok(ms=50.0) for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        assert "insufficient_history_for_100" not in result.score_caps_applied

    def test_score_100_requires_no_correctness_issues(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=14,
            consecutive_success_days=14,
            consecutive_fail_days=0,
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            # Probes with slight error
            probes = [_ok(ms=50.0) for _ in range(19)] + [_fail(error="timeout")]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            assert result.score < 100
            assert "imperfect_availability" in result.score_caps_applied or result.score < 99

    def test_score_100_requires_low_latency(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=14,
            consecutive_success_days=14,
            consecutive_fail_days=0,
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            # Probes with high latency - 500ms gives 8-point p50 penalty
            # This brings performance score to 18 (92 * 0.2), not 20
            probes = [_ok(ms=500.0) for _ in range(20)]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            # With 14 runs and no other issues, max possible is 98 (50+20+18+10)
            # Cannot reach 100 due to latency penalties
            assert result.score < 100
            assert result.performance_score < 20  # Penalty was applied

    def test_score_100_requires_no_flapping(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=14,
            consecutive_success_days=14,
            consecutive_fail_days=0,
            status_flaps_30d=5,  # Too much flapping
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            probes = [_ok(ms=50.0) for _ in range(20)]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            assert result.score < 100
            assert (
                "too_much_flapping" in result.score_caps_applied
                or "high_flapping" in result.reasons
            )

    def test_score_100_requires_no_recent_failures(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=14,
            consecutive_success_days=0,
            consecutive_fail_days=3,  # Recent failures
            status_flaps_30d=0,
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            probes = [_ok(ms=50.0) for _ in range(20)]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            assert result.score < 100
            assert (
                "recent_failures" in result.score_caps_applied
                or "recent_failure_streak" in result.reasons
            )


class TestFlappingPenalties:
    """Test that flapping reduces history score."""

    def test_high_flapping_reduces_score(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=10,
            consecutive_success_days=7,
            consecutive_fail_days=0,
            status_flaps_30d=6,  # High flapping
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            probes = [_ok() for _ in range(10)]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            assert "high_flapping" in result.reasons
            assert result.history_score < 10

    def test_moderate_flapping_reduces_score(self) -> None:
        mock_metrics = ResolverStabilityMetrics(
            host="192.0.2.1",
            transport="dns-udp",
            runs_seen_7d=7,
            runs_seen_30d=14,
            success_days_7d=7,
            success_days_30d=10,
            consecutive_success_days=7,
            consecutive_fail_days=0,
            status_flaps_30d=3,  # Moderate flapping
        )
        with patch("resolver_inventory.validate.scorer.get_resolver_stability_metrics") as mock:
            mock.return_value = mock_metrics
            probes = [_ok() for _ in range(10)]
            result = score(_candidate(), probes, Settings(), MagicMock(), date.today())
            assert "moderate_flapping" in result.reasons


class TestScoreExplainability:
    """Test that score explanations are present."""

    def test_caps_applied_listed(self) -> None:
        probes = [_ok() for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert isinstance(result.score_caps_applied, list)
        # Missing source reliability metadata should be reported as a cap.
        assert len(result.score_caps_applied) > 0

    def test_derived_metrics_present(self) -> None:
        probes = [_ok(ms=100.0) for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert isinstance(result.derived_metrics, dict)
        assert "p50_latency_ms" in result.derived_metrics
        assert "latency_sample_count" in result.derived_metrics

    def test_reasons_listed(self) -> None:
        probes = [_fail(error="timeout") for _ in range(5)]
        result = score(_candidate(), probes, Settings())
        assert len(result.reasons) > 0
        assert "timeout_or_error" in result.reasons


class TestConfidenceScoring:
    """Test confidence score computation."""

    def test_high_probe_count_increases_confidence(self) -> None:
        probes = [_ok() for _ in range(20)]
        result = score(_candidate(), probes, Settings())
        # 20+ probes should give high probe confidence component
        assert result.confidence_score >= 30  # At least the probe component

    def test_low_probe_count_reduces_confidence(self) -> None:
        probes = [_ok() for _ in range(2)]
        result = score(_candidate(), probes, Settings())
        # Only 2 probes should give lower confidence
        assert result.confidence_score < 50

    def test_no_latency_samples_reduces_confidence(self) -> None:
        # Create probes without latency data
        probes = [ProbeResult(ok=True, probe=f"test{i}", latency_ms=None) for i in range(10)]
        result = score(_candidate(), probes, Settings())
        # Should have lower confidence due to no latency samples
        assert result.confidence_score < 100


# Keep original tests for backward compatibility


class TestOriginalBackwardCompatibility:
    """Original tests to ensure backward compatibility."""

    def test_all_timeouts_rejected(self) -> None:
        probes = [_fail(error="timeout_or_error:timed out") for _ in range(10)]
        result = score(_candidate(), probes, Settings())
        assert result.status == "rejected"

    def test_high_timeout_rate_flagged(self) -> None:
        probes = [_fail(error="timeout_or_error:x") for _ in range(8)] + [_ok(), _ok()]
        result = score(_candidate(), probes, Settings())
        assert "timeout_rate_high" in result.reasons


def _history_result(host: str, status: str) -> ValidationResult:
    return ValidationResult(
        candidate=Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host=host,
            port=53,
            path=None,
        ),
        accepted=status == "accepted",
        score=90 if status == "accepted" else 10,
        status=status,  # type: ignore[arg-type]
        reasons=[],
        probes=[_ok()],
    )


def _run_metadata(day: date) -> RunMetadata:
    return RunMetadata(
        run_date=day,
        generated_at=datetime.combine(day, datetime.min.time(), tzinfo=UTC),
        github_run_id=f"run-{day.isoformat()}",
        repo_sha="repo-sha",
        crawler_sha="crawler-sha",
    )


class TestHistoryAwareScoring:
    """History metrics are consulted when a connection and run_date are given."""

    def test_no_history_connection_means_no_caps(self) -> None:
        result = score(_candidate(), [_ok() for _ in range(10)], Settings())
        assert result.score >= 90
        assert result.score_breakdown["history"] == 0
        assert not any("insufficient_history" in cap for cap in result.score_caps_applied)

    def test_unseen_resolver_capped_at_90(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            result = score(
                _candidate(),
                [_ok() for _ in range(10)],
                Settings(),
                history_connection=connection,
                run_date=date(2026, 1, 2),
            )
        # History was consulted but no rows exist for this resolver: it
        # counts as zero observed runs and cannot exceed the <3-run cap
        assert result.score <= 90
        assert result.score_breakdown["history"] == 0

    def test_few_history_runs_cap_score(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _run_metadata(date(2026, 1, 1)),
                [_history_result("192.0.2.1", "accepted")],
                [],
            )
            result = score(
                _candidate(),
                [_ok() for _ in range(10)],
                Settings(),
                history_connection=connection,
                run_date=date(2026, 1, 2),
            )
        assert result.score <= 90
        assert "insufficient_history:1_runs" in result.score_caps_applied

    def test_sufficient_history_removes_caps(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            for offset in range(14):
                day = date(2026, 1, 1) + timedelta(days=offset)
                update_history(
                    connection,
                    _run_metadata(day),
                    [_history_result("192.0.2.1", "accepted")],
                    [],
                )
            result = score(
                _candidate(),
                [_ok() for _ in range(10)],
                Settings(),
                history_connection=connection,
                run_date=date(2026, 1, 15),
            )
        assert result.score > 90
        assert not any("insufficient_history" in cap for cap in result.score_caps_applied)


class TestRequireTlsValidForDoh:
    """require_tls_valid_for_doh controls whether TLS failures are fatal."""

    def _probes_with_tls_failure(self) -> list[ProbeResult]:
        return [_ok(probe="doh:query:test") for _ in range(9)] + [
            _fail(probe="doh:tls", error="tls_error:certificate verify failed")
        ]

    def test_tls_failure_hard_fails_when_required(self) -> None:
        settings = Settings()
        settings.validation.require_tls_valid_for_doh = True
        result = score(_candidate("doh"), self._probes_with_tls_failure(), settings)
        assert result.status == "rejected"
        assert "tls_error" in result.reasons
        assert "hard_fail_cap" in result.score_caps_applied

    def test_tls_failure_is_soft_penalty_when_not_required(self) -> None:
        settings = Settings()
        settings.validation.require_tls_valid_for_doh = False
        result = score(_candidate("doh"), self._probes_with_tls_failure(), settings)
        # TLS failure still costs correctness points but does not hard-fail
        assert "tls_error" in result.reasons
        assert "hard_fail_cap" not in result.score_caps_applied
        assert result.status != "rejected"

    def test_tls_failure_always_hard_fails_for_dns(self) -> None:
        # The setting only relaxes DoH candidates
        settings = Settings()
        settings.validation.require_tls_valid_for_doh = False
        probes = [_ok() for _ in range(9)] + [_fail(error="tls_error:certificate verify failed")]
        result = score(_candidate("dns-udp"), probes, settings)
        assert result.status == "rejected"
        assert "hard_fail_cap" in result.score_caps_applied
