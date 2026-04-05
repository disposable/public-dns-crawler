"""Scoring engine: converts probe results into a ValidationResult."""

from __future__ import annotations

from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.settings import Settings

_REASON_WEIGHTS: dict[str, int] = {
    "nxdomain_spoofing": -50,
    "tls_name_mismatch": -40,
    "tls_error": -40,
    "doh_path_invalid": -30,
    "answer_mismatch": -30,
    "unexpected_nxdomain": -20,
    "unexpected_rcode": -15,
    "timeout_or_error": -10,
    "http_error": -15,
    "connect_error": -15,
    "error": -10,
}

# Latency penalty tiers (applied to median latency across successful probes).
# Thresholds in ms → penalty points deducted from raw_score.
_LATENCY_TIERS: list[tuple[int, int]] = [
    (1500, 30),  # > 1500 ms: severe
    (700, 18),   # 700–1500 ms: high
    (300, 8),    # 300–700 ms: moderate
    (100, 3),    # 100–300 ms: slight
]

# Reliability penalty tiers (from upstream source metadata, e.g. public-dns.info).
# Thresholds are fractions [0.0, 1.0] → penalty points.
_RELIABILITY_TIERS: list[tuple[float, int]] = [
    (0.55, 30),  # < 0.55 → very unreliable
    (0.70, 20),  # 0.55–0.70
    (0.85, 10),  # 0.70–0.85
    (0.95, 3),   # 0.85–0.95
]


def _classify_error(error: str) -> str:
    """Map a raw probe error string to a canonical reason code."""
    if error.startswith("nxdomain_spoofing"):
        return "nxdomain_spoofing"
    if "tls_name_mismatch" in error or "tls_error" in error:
        return "tls_name_mismatch"
    if error.startswith("timeout"):
        return "timeout_rate_high"
    if error.startswith("http_error"):
        return "http_error"
    if error.startswith("connect_error"):
        return "connect_error"
    if error.startswith("unexpected_nxdomain"):
        return "unexpected_nxdomain"
    if error.startswith("unexpected_rcode"):
        return "unexpected_rcode"
    return "error"


def score(
    candidate: Candidate,
    probes: list[ProbeResult],
    settings: Settings,
) -> ValidationResult:
    """Compute a ValidationResult from raw probe outputs."""
    if not probes:
        return ValidationResult(
            candidate=candidate,
            accepted=False,
            score=0,
            status="rejected",
            reasons=["no_probes"],
            probes=[],
        )

    total = len(probes)
    passed = sum(1 for p in probes if p.ok)

    reasons: list[str] = []
    penalty = 0

    error_counts: dict[str, int] = {}
    for probe in probes:
        if not probe.ok and probe.error:
            reason = _classify_error(probe.error)
            error_counts[reason] = error_counts.get(reason, 0) + 1

    for reason, count in error_counts.items():
        if reason not in reasons:
            reasons.append(reason)
        weight = _REASON_WEIGHTS.get(reason, -10)
        penalty += abs(weight) * count

    timeout_count = sum(1 for p in probes if not p.ok and p.error and "timeout" in p.error)
    timeout_rate = timeout_count / total if total else 0.0
    if timeout_rate > 0.5:
        if "timeout_rate_high" not in reasons:
            reasons.append("timeout_rate_high")

    success_rate = passed / total if total else 0.0
    base_score = int(success_rate * 100)
    raw_score = max(0, min(100, base_score - penalty))

    # --- Latency penalty (based on median latency of successful probes) ---
    latencies = [p.latency_ms for p in probes if p.ok and p.latency_ms is not None]
    if latencies:
        sorted_l = sorted(latencies)
        mid = len(sorted_l) // 2
        median_latency = (
            (sorted_l[mid - 1] + sorted_l[mid]) / 2.0
            if len(sorted_l) % 2 == 0
            else sorted_l[mid]
        )
        for threshold_ms, pts in _LATENCY_TIERS:
            if median_latency > threshold_ms:
                raw_score = max(0, raw_score - pts)
                if threshold_ms >= 1500 and "latency_very_high" not in reasons:
                    reasons.append("latency_very_high")
                elif threshold_ms >= 700 and "latency_high" not in reasons:
                    reasons.append("latency_high")
                break

        p95_idx = int(len(sorted_l) * 0.95)
        p95 = sorted_l[min(p95_idx, len(sorted_l) - 1)]
        if p95 > 2000 and "latency_p95_high" not in reasons:
            reasons.append("latency_p95_high")

    # --- Reliability penalty (from upstream source metadata) ---
    reliability_str = candidate.metadata.get("reliability")
    if reliability_str is not None:
        try:
            reliability = float(reliability_str)
            for threshold, pts in _RELIABILITY_TIERS:
                if reliability < threshold:
                    raw_score = max(0, raw_score - pts)
                    if threshold <= 0.55 and "reliability_low" not in reasons:
                        reasons.append("reliability_low")
                    break
        except ValueError:
            pass

    accept_min = settings.scoring.accept_min_score
    candidate_min = settings.scoring.candidate_min_score

    if raw_score >= accept_min and not _has_hard_fail(reasons):
        status = "accepted"
        accepted = True
    elif raw_score >= candidate_min and not _has_hard_fail(reasons):
        status = "candidate"
        accepted = False
    else:
        status = "rejected"
        accepted = False

    if candidate.transport in ("dns-udp",) and not any(
        p.probe.startswith("dns-tcp") for p in probes
    ):
        if "udp_only" not in reasons:
            reasons.append("udp_only")

    return ValidationResult(
        candidate=candidate,
        accepted=accepted,
        score=raw_score,
        status=status,
        reasons=reasons,
        probes=probes,
    )


_HARD_FAIL_REASONS = {"nxdomain_spoofing", "tls_name_mismatch"}


def _has_hard_fail(reasons: list[str]) -> bool:
    return bool(_HARD_FAIL_REASONS.intersection(reasons))
