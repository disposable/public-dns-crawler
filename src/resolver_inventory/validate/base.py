"""Shared helpers for validators."""

from __future__ import annotations

from resolver_inventory.models import ProbeResult


def ok_probe(probe: str, latency_ms: float, details: dict[str, str] | None = None) -> ProbeResult:
    return ProbeResult(ok=True, probe=probe, latency_ms=latency_ms, details=details or {})


def fail_probe(probe: str, error: str, details: dict[str, str] | None = None) -> ProbeResult:
    return ProbeResult(ok=False, probe=probe, error=error, details=details or {})
