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

    latencies = [p.latency_ms for p in probes if p.ok and p.latency_ms is not None]
    if latencies:
        sorted_l = sorted(latencies)
        p95_idx = int(len(sorted_l) * 0.95)
        p95 = sorted_l[min(p95_idx, len(sorted_l) - 1)]
        if p95 > 2000:
            if "latency_p95_high" not in reasons:
                reasons.append("latency_p95_high")

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
