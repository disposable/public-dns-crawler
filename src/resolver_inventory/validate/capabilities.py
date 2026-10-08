"""Capability checks: non-scoring resolver property measurements.

Each check produces a ``capability:{name}`` ProbeResult that is always
``ok=True`` - failures to measure are reported as ``null`` in the result's
``capabilities`` mapping rather than as probe failures. The scorer partitions
these probes out of all score math and lifts their details into
``ValidationResult.capabilities``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol

import dns.edns
import dns.message
import dns.rcode
import dns.rdatatype

from resolver_inventory.models import ProbeResult
from resolver_inventory.settings import CapabilitiesConfig
from resolver_inventory.util.logging import get_logger

logger = get_logger(__name__)

# Answers that indicate a sinkholed/filtered response rather than a real one.
_SINKHOLE_ANSWERS = frozenset({"0.0.0.0", "::"})

# Check name -> canonical capability key emitted in probe details.
_CAPABILITY_KEY_BY_NAME = {
    "dnssec": "dnssec_validating",
    "ecs": "ecs_support",
    "filtering": "filters_detected",
}


class CapabilityQueryExecutor(Protocol):
    """Transport-specific query primitive used by capability checks."""

    async def __call__(
        self,
        qname: str,
        rdtype: str,
        *,
        want_dnssec: bool = False,
        ecs: tuple[str, int] | None = None,
    ) -> dns.message.Message: ...


def capability_check_names(config: CapabilitiesConfig) -> list[str]:
    """Names of capability checks enabled by configuration."""
    if not config.enabled:
        return []
    names: list[str] = []
    if config.dnssec_sentinels:
        names.append("dnssec")
    if config.ecs_probe_qname:
        names.append("ecs")
    if config.filter_domains:
        names.append("filtering")
    return names


async def run_capability_check(
    name: str,
    execute: CapabilityQueryExecutor,
    config: CapabilitiesConfig,
    *,
    resolve_baseline: Callable[[str, str], Awaitable[list[str]]] | None = None,
) -> ProbeResult:
    """Run one capability check and wrap the outcome in a ProbeResult."""
    if not config.enabled:
        return ProbeResult(
            ok=True,
            probe=f"capability:{name}",
            details={_CAPABILITY_KEY_BY_NAME.get(name, name): "unknown"},
        )
    try:
        if name == "dnssec":
            details = await _check_dnssec(execute, config.dnssec_sentinels)
        elif name == "ecs":
            details = await _check_ecs(execute, config.ecs_probe_qname)
        elif name == "filtering":
            details = await _check_filtering(execute, config.filter_domains, resolve_baseline)
        else:
            details = {_CAPABILITY_KEY_BY_NAME.get(name, name): "unknown", "error": "unknown_check"}
    except Exception as exc:  # never let a capability check crash validation
        logger.debug("capability check %s failed: %s", name, exc)
        details = {_CAPABILITY_KEY_BY_NAME.get(name, name): "unknown", "error": str(exc)[:80]}
    return ProbeResult(ok=True, probe=f"capability:{name}", details=details)


async def _check_dnssec(execute: CapabilityQueryExecutor, sentinels: list[str]) -> dict[str, str]:
    """A validating resolver returns SERVFAIL for broken-signature domains."""
    saw_servfail = False
    for qname in sentinels:
        try:
            resp = await execute(qname, "A", want_dnssec=True)
        except Exception:
            continue
        if resp.rcode() == dns.rcode.SERVFAIL:
            saw_servfail = True
        else:
            # The resolver answered a deliberately-broken domain: it does not
            # validate DNSSEC.
            return {"dnssec_validating": "false"}
    return {"dnssec_validating": "true" if saw_servfail else "unknown"}


async def _check_ecs(execute: CapabilityQueryExecutor, qname: str) -> dict[str, str]:
    """Detect whether the resolver reflects EDNS Client Subnet upstream."""
    try:
        resp = await execute(qname, "A", ecs=("192.0.2.0", 24))
    except Exception:
        return {"ecs_support": "unknown"}
    for option in resp.options:
        if isinstance(option, dns.edns.ECSOption):
            return {"ecs_support": "true"}
    return {"ecs_support": "false"}


async def _check_filtering(
    execute: CapabilityQueryExecutor,
    domains: list[str],
    resolve_baseline: Callable[[str, str], Awaitable[list[str]]] | None,
) -> dict[str, str]:
    """Tag resolvers that block domains which baseline resolvers resolve."""
    blocked: list[str] = []
    saw_answer = False
    for qname in domains:
        try:
            resp = await execute(qname, "A")
        except Exception:
            continue
        # Only conclusive responses count: an error rcode (REFUSED,
        # SERVFAIL, ...) is no evidence either way.
        if resp.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
            continue
        saw_answer = True
        answers = {
            rdata.address
            for rrset in resp.answer
            if rrset.rdtype == dns.rdatatype.A
            for rdata in rrset
        }
        sinkholed = bool(answers) and answers.issubset(_SINKHOLE_ANSWERS)
        nxdomain = resp.rcode() == dns.rcode.NXDOMAIN
        if not (sinkholed or nxdomain):
            continue
        # Only count as filtered when the baseline resolves real answers.
        if resolve_baseline is None:
            continue
        try:
            baseline = await resolve_baseline(qname, "A")
        except Exception:
            baseline = []
        if {a for a in baseline if a not in _SINKHOLE_ANSWERS}:
            blocked.append(qname)
    if blocked:
        return {"filters_detected": "true", "filtered_domains": ",".join(blocked)}
    return {"filters_detected": "false" if saw_answer else "unknown"}


def parse_capability_probes(probes: list[ProbeResult]) -> dict[str, bool | None]:
    """Lift ``capabilities`` values out of capability ProbeResult details."""
    capabilities: dict[str, bool | None] = {}
    for probe in probes:
        if not probe.probe.startswith("capability:"):
            continue
        for key, value in probe.details.items():
            if key == "error" or key == "filtered_domains":
                continue
            capabilities[key] = _str_to_bool_or_none(value)
    return capabilities


def _str_to_bool_or_none(value: str) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None
