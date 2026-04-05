"""Scoring engine: converts probe results into a ValidationResult with detailed components."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import TYPE_CHECKING

from resolver_inventory.history import (
    SEVERE_CORRECTNESS_REASONS,
    ResolverStabilityMetrics,
    get_resolver_stability_metrics,
    normalize_resolver_key,
)
from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings

if TYPE_CHECKING:
    import duckdb

# --- Configuration: Severity weights for correctness issues ---
# These are penalty amounts that reduce the correctness_score component.
_SEVERITY_PENALTIES: dict[str, int] = {
    "nxdomain_spoofing": 50,
    "tls_name_mismatch": 40,
    "tls_error": 30,
    "doh_path_invalid": 25,
    "answer_mismatch": 25,
    "unexpected_nxdomain": 15,
    "unexpected_rcode": 10,
    "timeout_or_error": 5,
    "http_error": 10,
    "connect_error": 10,
    "error": 5,
}

# Hard-fail reasons that cap the final score regardless of other factors
_HARD_FAIL_REASONS: frozenset[str] = frozenset(
    set(SEVERE_CORRECTNESS_REASONS).union({"unexpected_rcode_suspicious"})
)

# --- Configuration: Latency penalty tiers ---
# (threshold_ms, penalty_points)
_P50_LATENCY_TIERS: list[tuple[int, int]] = [
    (1500, 30),  # > 1500 ms: severe
    (700, 18),  # 700-1500 ms: high
    (300, 8),  # 300-700 ms: moderate
    (100, 3),  # 100-300 ms: slight
]

_P95_LATENCY_TIERS: list[tuple[int, int]] = [
    (2500, 20),  # > 2500 ms: severe
    (1500, 12),  # 1500-2500 ms: high
    (800, 6),  # 800-1500 ms: moderate
    (400, 2),  # 400-800 ms: slight
]

_JITTER_TIERS: list[tuple[int, int]] = [
    (900, 12),  # > 900 ms: severe jitter
    (400, 6),  # 400-900 ms: high jitter
    (150, 2),  # 150-400 ms: moderate jitter
]

# --- Configuration: Source reliability tiers ---
# (threshold_fraction, penalty_points)
_RELIABILITY_TIERS: list[tuple[float, int]] = [
    (0.55, 15),  # < 0.55: very unreliable
    (0.70, 10),  # 0.55-0.70
    (0.85, 5),  # 0.70-0.85
    (0.95, 2),  # 0.85-0.95
]

# --- Configuration: Score caps based on observation history ---
_HISTORY_CAPS: list[tuple[int, int]] = [
    (3, 90),  # 0-2 runs: max 90 (runs < 3)
    (7, 95),  # 3-6 runs: max 95 (runs < 7)
    (14, 98),  # 7-13 runs: max 98 (runs < 14)
]

# Minimum runs required for a score of 100
_MIN_RUNS_FOR_PERFECT_SCORE = 14

# Maximum flaps allowed for a score of 100
_MAX_FLAPS_FOR_PERFECT_SCORE = 2


@dataclass
class ScoreComponents:
    """Individual scoring components before weighting."""

    # Raw component scores (0-100 scale, before weighting)
    correctness_raw: int = 100
    availability_raw: int = 100
    performance_raw: int = 100
    history_raw: int = 0  # Starts at 0, gains points for good history

    # Penalties applied (for reporting)
    correctness_penalties: dict[str, int] = field(default_factory=dict)
    performance_penalties: dict[str, int] = field(default_factory=dict)

    # Final weighted scores (0-100 scale after applying weights)
    correctness: int = 0
    availability: int = 0
    performance: int = 0
    history: int = 0

    # Confidence in the measurement (0-100)
    confidence: int = 0

    # Score caps that were applied
    caps_applied: list[str] = field(default_factory=list)

    # Derived metrics for reporting
    derived_metrics: dict[str, float | int | None] = field(default_factory=dict)


@dataclass
class LatencyStats:
    """Computed latency statistics from successful probes."""

    p50_ms: float | None = None
    p95_ms: float | None = None
    jitter_ms: float | None = None
    sample_count: int = 0


def _compute_latency_stats(probes: list[ProbeResult]) -> LatencyStats:
    """Compute p50, p95, and jitter from successful probes."""
    latencies = [p.latency_ms for p in probes if p.ok and p.latency_ms is not None]
    if not latencies:
        return LatencyStats()

    latencies.sort()
    n = len(latencies)
    mid = n // 2
    p50 = (latencies[mid - 1] + latencies[mid]) / 2.0 if n % 2 == 0 else latencies[mid]
    p95_idx = int(n * 0.95)
    p95 = latencies[min(p95_idx, n - 1)]
    jitter = max(0.0, p95 - p50)

    return LatencyStats(
        p50_ms=p50,
        p95_ms=p95,
        jitter_ms=jitter,
        sample_count=n,
    )


def _classify_error(error: str) -> str:
    """Map a raw probe error string to a canonical reason code."""
    if error.startswith("nxdomain_spoofing"):
        return "nxdomain_spoofing"
    if "tls_name_mismatch" in error:
        return "tls_name_mismatch"
    if "tls_error" in error:
        return "tls_error"
    if error.startswith("timeout"):
        return "timeout_or_error"
    if error.startswith("http_error"):
        return "http_error"
    if error.startswith("connect_error"):
        return "connect_error"
    if error.startswith("doh_path_invalid"):
        return "doh_path_invalid"
    if error.startswith("answer_mismatch"):
        return "answer_mismatch"
    if error.startswith("unexpected_nxdomain"):
        return "unexpected_nxdomain"
    if error.startswith("unexpected_rcode"):
        # Check if this looks like suspicious behavior
        if "REFUSED" in error or "SERVFAIL" in error:
            return "unexpected_rcode_suspicious"
        return "unexpected_rcode"
    return "error"


def _score_correctness(
    probes: list[ProbeResult],
    components: ScoreComponents,
    reasons: list[str],
) -> int:
    """Score correctness component (0-50 weight in final score).

    Returns the weighted correctness score (0-50).
    """
    if not probes:
        components.correctness_penalties["no_probes"] = 50
        components.correctness_raw = 0
        reasons.append("no_probes")
        return 0

    # Count errors and their severity
    error_counts: dict[str, int] = {}
    for probe in probes:
        if not probe.ok and probe.error:
            reason = _classify_error(probe.error)
            error_counts[reason] = error_counts.get(reason, 0) + 1
            if reason not in reasons:
                reasons.append(reason)

    # Apply severity penalties to raw correctness score
    penalty_total = 0
    for reason, count in error_counts.items():
        weight = _SEVERITY_PENALTIES.get(reason, 5)
        penalty = weight * count
        penalty_total += penalty
        components.correctness_penalties[reason] = penalty

    # Also penalize for timeout rate if high
    timeout_count = sum(1 for p in probes if not p.ok and p.error and "timeout" in p.error)
    timeout_rate = timeout_count / len(probes) if probes else 0.0
    if timeout_rate > 0.5:
        if "timeout_rate_high" not in reasons:
            reasons.append("timeout_rate_high")
        timeout_penalty = int(20 * timeout_rate)
        components.correctness_penalties["timeout_rate_high"] = timeout_penalty
        penalty_total += timeout_penalty

    components.correctness_raw = max(0, 100 - penalty_total)
    # Weight: correctness is 0-50 in final score
    return int(components.correctness_raw * 0.5)


def _score_availability(probes: list[ProbeResult]) -> int:
    """Score availability component (0-20 weight in final score).

    Based purely on success rate of probes.
    """
    if not probes:
        return 0

    total = len(probes)
    passed = sum(1 for p in probes if p.ok)
    success_rate = passed / total

    # Map success rate to 0-20 scale
    # 100% success = 20 points
    # 90% success = 18 points
    # 80% success = 16 points
    # 70% success = 14 points
    # 60% success = 12 points
    # 50% success = 10 points
    # Below 50%: linear down to 0
    if success_rate >= 0.99:
        return 20
    if success_rate >= 0.95:
        return 19
    if success_rate >= 0.90:
        return 18
    if success_rate >= 0.85:
        return 17
    if success_rate >= 0.80:
        return 16
    if success_rate >= 0.75:
        return 15
    if success_rate >= 0.70:
        return 14
    if success_rate >= 0.65:
        return 13
    if success_rate >= 0.60:
        return 12
    if success_rate >= 0.55:
        return 11
    if success_rate >= 0.50:
        return 10
    # Below 50%: proportional to success rate
    return int(success_rate * 20)


def _score_performance(
    probes: list[ProbeResult],
    components: ScoreComponents,
    reasons: list[str],
) -> int:
    """Score performance component (0-20 weight in final score).

    Based on p50, p95, and jitter with numeric penalties.
    """
    stats = _compute_latency_stats(probes)
    components.derived_metrics["p50_latency_ms"] = stats.p50_ms
    components.derived_metrics["p95_latency_ms"] = stats.p95_ms
    components.derived_metrics["jitter_ms"] = stats.jitter_ms
    components.derived_metrics["latency_sample_count"] = stats.sample_count

    if stats.sample_count == 0:
        components.performance_raw = 0
        reasons.append("no_latency_samples")
        return 0

    # Start with perfect performance score
    performance_score = 100

    # Apply p50 penalties
    if stats.p50_ms is not None:
        for threshold_ms, penalty in _P50_LATENCY_TIERS:
            if stats.p50_ms > threshold_ms:
                performance_score -= penalty
                components.performance_penalties[f"p50>{threshold_ms}ms"] = penalty
                if threshold_ms >= 1500 and "latency_very_high" not in reasons:
                    reasons.append("latency_very_high")
                elif threshold_ms >= 700 and "latency_high" not in reasons:
                    reasons.append("latency_high")
                elif "latency_moderate" not in reasons:
                    reasons.append("latency_moderate")
                break

    # Apply p95 penalties
    if stats.p95_ms is not None:
        for threshold_ms, penalty in _P95_LATENCY_TIERS:
            if stats.p95_ms > threshold_ms:
                performance_score -= penalty
                components.performance_penalties[f"p95>{threshold_ms}ms"] = penalty
                if threshold_ms >= 1500 and "latency_p95_high" not in reasons:
                    reasons.append("latency_p95_high")
                break

    # Apply jitter penalties
    if stats.jitter_ms is not None:
        for threshold_ms, penalty in _JITTER_TIERS:
            if stats.jitter_ms > threshold_ms:
                performance_score -= penalty
                components.performance_penalties[f"jitter>{threshold_ms}ms"] = penalty
                if threshold_ms >= 400 and "latency_jitter_high" not in reasons:
                    reasons.append("latency_jitter_high")
                break

    components.performance_raw = max(0, performance_score)
    # Weight: performance is 0-20 in final score
    return int(components.performance_raw * 0.2)


def _score_history(
    metrics: ResolverStabilityMetrics | None,
    components: ScoreComponents,
    reasons: list[str],
) -> int:
    """Score history component (0-10 weight in final score).

    Rewards sustained stability, penalizes flapping and recent failures.
    """
    if metrics is None:
        components.derived_metrics["runs_seen_30d"] = None
        components.derived_metrics["runs_seen_7d"] = None
        components.derived_metrics["flaps_30d"] = None
        return 0

    # Record derived metrics
    components.derived_metrics["runs_seen_30d"] = metrics.runs_seen_30d
    components.derived_metrics["runs_seen_7d"] = metrics.runs_seen_7d
    components.derived_metrics["flaps_30d"] = metrics.status_flaps_30d
    components.derived_metrics["consecutive_success_days"] = metrics.consecutive_success_days
    components.derived_metrics["consecutive_fail_days"] = metrics.consecutive_fail_days

    # Start with base history score
    history_score = 0

    # Reward for having observed history
    if metrics.runs_seen_30d >= 14:
        history_score += 4  # Good observation baseline
    elif metrics.runs_seen_30d >= 7:
        history_score += 2
    elif metrics.runs_seen_30d >= 3:
        history_score += 1

    # Reward for 30-day success rate
    if metrics.runs_seen_30d > 0:
        success_ratio = metrics.success_days_30d / metrics.runs_seen_30d
        if success_ratio >= 0.95:
            history_score += 3
        elif success_ratio >= 0.85:
            history_score += 2
        elif success_ratio >= 0.70:
            history_score += 1

    # Reward for recent (7-day) success
    if metrics.runs_seen_7d > 0:
        recent_success_ratio = metrics.success_days_7d / metrics.runs_seen_7d
        if recent_success_ratio >= 0.95:
            history_score += 2
        elif recent_success_ratio >= 0.80:
            history_score += 1

    # Reward for consecutive success days
    if metrics.consecutive_success_days >= 14:
        history_score += 1

    # Penalize for flapping
    if metrics.status_flaps_30d >= 5:
        history_score -= 4
        reasons.append("high_flapping")
    elif metrics.status_flaps_30d >= 3:
        history_score -= 2
        reasons.append("moderate_flapping")

    # Penalize for recent failure streak
    if metrics.consecutive_fail_days >= 3:
        history_score -= 3
        reasons.append("recent_failure_streak")
    elif metrics.consecutive_fail_days >= 1:
        history_score -= 1

    components.history_raw = max(0, history_score)
    return components.history_raw  # Already 0-10 scale


def _compute_confidence(
    probes: list[ProbeResult],
    metrics: ResolverStabilityMetrics | None,
    candidate: Candidate,
    components: ScoreComponents,
) -> int:
    """Compute confidence score (0-100) separate from quality score.

    Confidence reflects certainty in the measurement, not resolver quality.
    """
    confidence = 0

    # Base confidence from probe count (max 30)
    total_probes = len(probes)

    if total_probes >= 20:
        confidence += 30
    elif total_probes >= 10:
        confidence += 25
    elif total_probes >= 5:
        confidence += 15
    elif total_probes >= 3:
        confidence += 10
    else:
        confidence += 5

    # Confidence from latency samples (max 20)
    latency_samples = components.derived_metrics.get("latency_sample_count", 0)
    if isinstance(latency_samples, int):
        if latency_samples >= 15:
            confidence += 20
        elif latency_samples >= 8:
            confidence += 15
        elif latency_samples >= 4:
            confidence += 10
        elif latency_samples >= 1:
            confidence += 5

    # Confidence from historical observation (max 35)
    if metrics is not None:
        if metrics.runs_seen_30d >= 21:
            confidence += 35
        elif metrics.runs_seen_30d >= 14:
            confidence += 30
        elif metrics.runs_seen_30d >= 7:
            confidence += 20
        elif metrics.runs_seen_30d >= 3:
            confidence += 10
        else:
            confidence += 5
    # else: no history — no confidence points from this component

    # Confidence from source metadata (max 15)
    reliability_str = candidate.metadata.get("reliability")
    if reliability_str is not None:
        try:
            reliability = float(reliability_str)
            if reliability >= 0.95:
                confidence += 15
            elif reliability >= 0.85:
                confidence += 12
            elif reliability >= 0.70:
                confidence += 8
            else:
                confidence += 5
        except ValueError:
            confidence += 5
    else:
        # Missing reliability metadata reduces confidence
        confidence += 5
        if "source_reliability_unknown" not in components.caps_applied:
            components.caps_applied.append("source_reliability_unknown")

    return min(100, confidence)


def _apply_source_reliability_penalty(
    candidate: Candidate,
    current_score: int,
    components: ScoreComponents,
    reasons: list[str],
) -> int:
    """Apply penalty for low source reliability, but don't treat missing as good."""
    reliability_str = candidate.metadata.get("reliability")

    if reliability_str is None:
        # Missing reliability: don't penalize score directly, confidence handles this
        return current_score

    try:
        reliability = float(reliability_str)
        for threshold, penalty in _RELIABILITY_TIERS:
            if reliability < threshold:
                if threshold <= 0.55 and "reliability_low" not in reasons:
                    reasons.append("reliability_low")
                # Apply penalty to the score
                return max(0, current_score - penalty)
    except ValueError:
        pass

    return current_score


def _apply_history_caps(
    metrics: ResolverStabilityMetrics | None,
    current_score: int,
    components: ScoreComponents,
) -> int:
    """Apply caps based on observation history."""
    if metrics is None:
        return current_score

    runs_seen = metrics.runs_seen_30d

    for min_runs, max_score in _HISTORY_CAPS:
        if runs_seen < min_runs:
            if current_score > max_score:
                components.caps_applied.append(f"insufficient_history:{runs_seen}_runs")
            return min(current_score, max_score)

    return current_score


def _apply_perfect_score_requirements(
    probes: list[ProbeResult],
    metrics: ResolverStabilityMetrics | None,
    components: ScoreComponents,
    reasons: list[str],
) -> int:
    """Determine if a score of 100 is allowed, otherwise clamp to 99."""
    # Check for any correctness issues
    if components.correctness_penalties:
        components.caps_applied.append("correctness_issues")
        return 99

    # Check for high latency
    if components.performance_penalties:
        components.caps_applied.append("performance_not_perfect")
        return 99

    # Check history requirements only when history exists.
    if metrics is None:
        return 100

    if metrics.runs_seen_30d < _MIN_RUNS_FOR_PERFECT_SCORE:
        components.caps_applied.append(f"insufficient_history_for_100:{metrics.runs_seen_30d}_runs")
        return 99

    if metrics.status_flaps_30d > _MAX_FLAPS_FOR_PERFECT_SCORE:
        components.caps_applied.append(f"too_much_flapping:{metrics.status_flaps_30d}_flaps")
        return 99

    if metrics.consecutive_fail_days > 0:
        components.caps_applied.append("recent_failures")
        return 99

    # Check for perfect availability
    if probes:
        success_rate = sum(1 for p in probes if p.ok) / len(probes)
        if success_rate < 1.0:
            components.caps_applied.append("imperfect_availability")
            return 99

    # Check confidence requirement
    if components.confidence < 90:
        components.caps_applied.append("low_confidence")
        return 99

    return 100


def _has_hard_fail(reasons: list[str]) -> bool:
    """Check if any hard-fail reasons are present."""
    return bool(_HARD_FAIL_REASONS.intersection(reasons))


def score(
    candidate: Candidate,
    probes: list[ProbeResult],
    settings: Settings,
    history_connection: duckdb.DuckDBPyConnection | None = None,
    run_date: date | None = None,
) -> ValidationResult:
    """Compute a detailed ValidationResult from raw probe outputs.

    Uses decomposed scoring components with explicit weights:
    - correctness: 0-50 (penalties for DNS/TLS errors, mismatches)
    - availability: 0-20 (probe success rate)
    - performance: 0-20 (p50, p95, jitter penalties)
    - history: 0-10 (stability over time)

    Confidence is computed separately and reflects measurement certainty.
    """
    reasons: list[str] = []
    components = ScoreComponents()

    # Get historical metrics if available
    metrics: ResolverStabilityMetrics | None = None
    if history_connection is not None and run_date is not None:
        try:
            resolver_key = normalize_resolver_key(candidate)
            metrics = get_resolver_stability_metrics(
                history_connection,
                resolver_key,
                run_date,
            )
        except Exception:
            # If history query fails, continue without it
            pass

    # Compute component scores
    components.correctness = _score_correctness(probes, components, reasons)
    components.availability = _score_availability(probes)
    components.performance = _score_performance(probes, components, reasons)
    components.history = _score_history(metrics, components, reasons)

    # Compute confidence separately
    components.confidence = _compute_confidence(probes, metrics, candidate, components)

    # Calculate final score as weighted sum
    final_score = (
        components.correctness
        + components.availability
        + components.performance
        + components.history
    )

    # Apply source reliability penalty
    final_score = _apply_source_reliability_penalty(candidate, final_score, components, reasons)

    # Apply history-based caps
    final_score = _apply_history_caps(metrics, final_score, components)

    # Apply perfect score requirements (100 -> 99 if not meeting criteria)
    if final_score >= 100:
        final_score = _apply_perfect_score_requirements(probes, metrics, components, reasons)

    # Check for hard-fail correctness issues and apply final clamp before status.
    has_hard_fail = _has_hard_fail(reasons)
    if has_hard_fail and final_score > 59:
        final_score = 59
        components.caps_applied.append("hard_fail_cap")

    # Determine acceptance status from the final clamped score.
    accept_min = settings.scoring.accept_min_score
    candidate_min = settings.scoring.candidate_min_score
    if not has_hard_fail and final_score >= accept_min:
        status = "accepted"
        accepted = True
    elif not has_hard_fail and final_score >= candidate_min:
        status = "candidate"
        accepted = False
    else:
        status = "rejected"
        accepted = False

    # Flag UDP-only transport (dns-udp candidates are never cross-tested with TCP)
    if candidate.transport == "dns-udp" and "udp_only" not in reasons:
        reasons.append("udp_only")

    return ValidationResult(
        candidate=candidate,
        accepted=accepted,
        score=final_score,
        status=status,
        reasons=reasons,
        probes=probes,
        correctness_score=components.correctness,
        availability_score=components.availability,
        performance_score=components.performance,
        history_score=components.history,
        confidence_score=components.confidence,
        score_breakdown={
            "correctness": components.correctness,
            "availability": components.availability,
            "performance": components.performance,
            "history": components.history,
        },
        score_caps_applied=components.caps_applied,
        derived_metrics=components.derived_metrics,
    )
