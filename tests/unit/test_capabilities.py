"""Unit tests for non-scoring capability checks."""

from __future__ import annotations

import dns.edns
import dns.message
import dns.rcode
import dns.rrset
import pytest

from resolver_inventory.models import Candidate, ProbeResult
from resolver_inventory.settings import CapabilitiesConfig, Settings
from resolver_inventory.validate.capabilities import (
    capability_check_names,
    parse_capability_probes,
    run_capability_check,
)
from resolver_inventory.validate.scorer import score


def _response(
    rcode: int = dns.rcode.NOERROR, answers: list[str] | None = None
) -> dns.message.Message:
    query = dns.message.make_query("example.test.", "A")
    msg = dns.message.make_response(query)
    msg.set_rcode(rcode)
    for address in answers or []:
        msg.answer.append(dns.rrset.from_text("example.test.", 60, "IN", "A", address))
    return msg


def _config(**overrides: object) -> CapabilitiesConfig:
    config = CapabilitiesConfig()
    for key, value in overrides.items():
        setattr(config, key, value)
    return config


class TestCapabilityCheckNames:
    def test_disabled_returns_empty(self) -> None:
        assert capability_check_names(_config(enabled=False)) == []

    def test_default_lists_all_checks(self) -> None:
        assert capability_check_names(CapabilitiesConfig()) == [
            "dnssec",
            "ecs",
            "filtering",
        ]

    def test_empty_check_lists_drop_names(self) -> None:
        names = capability_check_names(
            _config(dnssec_sentinels=[], ecs_probe_qname="", filter_domains=[])
        )
        assert names == []


class TestDnssecCheck:
    @pytest.mark.asyncio
    async def test_servfail_means_validating(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(rcode=dns.rcode.SERVFAIL)

        probe = await run_capability_check("dnssec", execute, _config())
        assert probe.ok
        assert probe.details["dnssec_validating"] == "true"

    @pytest.mark.asyncio
    async def test_answered_broken_domain_means_not_validating(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(answers=["192.0.2.1"])

        probe = await run_capability_check("dnssec", execute, _config())
        assert probe.details["dnssec_validating"] == "false"

    @pytest.mark.asyncio
    async def test_all_queries_fail_means_unknown(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            raise TimeoutError("no answer")

        probe = await run_capability_check("dnssec", execute, _config())
        assert probe.details["dnssec_validating"] == "unknown"


class TestEcsCheck:
    @pytest.mark.asyncio
    async def test_ecs_option_reflected(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            msg = _response(answers=["192.0.2.1"])
            msg.use_edns(0, options=[dns.edns.ECSOption("192.0.2.0", 24, 24)])
            return msg

        probe = await run_capability_check("ecs", execute, _config())
        assert probe.details["ecs_support"] == "true"

    @pytest.mark.asyncio
    async def test_no_ecs_option_means_unsupported(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(answers=["192.0.2.1"])

        probe = await run_capability_check("ecs", execute, _config())
        assert probe.details["ecs_support"] == "false"


class TestFilteringCheck:
    @pytest.mark.asyncio
    async def test_sinkholed_domain_with_real_baseline_is_filtered(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(answers=["0.0.0.0"])

        async def baseline(qname: str, rdtype: str) -> list[str]:
            return ["203.0.113.9"]

        probe = await run_capability_check(
            "filtering",
            execute,
            _config(filter_domains=["blocked.test."]),
            resolve_baseline=baseline,
        )
        assert probe.details["filters_detected"] == "true"
        assert probe.details["filtered_domains"] == "blocked.test."

    @pytest.mark.asyncio
    async def test_nxdomain_with_real_baseline_is_filtered(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(rcode=dns.rcode.NXDOMAIN)

        async def baseline(qname: str, rdtype: str) -> list[str]:
            return ["203.0.113.9"]

        probe = await run_capability_check(
            "filtering",
            execute,
            _config(filter_domains=["blocked.test."]),
            resolve_baseline=baseline,
        )
        assert probe.details["filters_detected"] == "true"

    @pytest.mark.asyncio
    async def test_real_answer_means_unfiltered(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(answers=["203.0.113.9"])

        probe = await run_capability_check(
            "filtering", execute, _config(filter_domains=["ads.test."])
        )
        assert probe.details["filters_detected"] == "false"

    @pytest.mark.asyncio
    async def test_sinkhole_matching_baseline_is_not_filtered(self) -> None:
        """A sinkholed answer isn't filtering if baselines sinkhole it too."""

        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(answers=["0.0.0.0"])

        async def baseline(qname: str, rdtype: str) -> list[str]:
            return ["0.0.0.0"]

        probe = await run_capability_check(
            "filtering",
            execute,
            _config(filter_domains=["blocked.test."]),
            resolve_baseline=baseline,
        )
        assert probe.details["filters_detected"] == "false"

    @pytest.mark.asyncio
    async def test_error_rcode_is_inconclusive_not_unfiltered(self) -> None:
        """REFUSED/SERVFAIL responses are not evidence of no-filtering."""

        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(rcode=dns.rcode.REFUSED)

        probe = await run_capability_check(
            "filtering", execute, _config(filter_domains=["ads.test."])
        )
        assert probe.details["filters_detected"] == "unknown"


class TestCapabilityProbeIsolation:
    def test_capability_probes_excluded_from_score_math(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host="192.0.2.1",
            port=53,
            path=None,
        )
        good_probes = [
            ProbeResult(ok=True, probe="positive:a", latency_ms=10.0),
            ProbeResult(ok=True, probe="positive:b", latency_ms=10.0),
        ]
        settings = Settings()
        baseline_result = score(candidate, list(good_probes), settings)
        with_caps = score(
            candidate,
            [
                *good_probes,
                ProbeResult(
                    ok=True,
                    probe="capability:dnssec",
                    details={"dnssec_validating": "true"},
                ),
                ProbeResult(
                    ok=True,
                    probe="capability:filtering",
                    details={"filters_detected": "false"},
                ),
            ],
            settings,
        )
        assert with_caps.score == baseline_result.score
        assert with_caps.correctness_score == baseline_result.correctness_score
        assert with_caps.availability_score == baseline_result.availability_score
        assert with_caps.confidence_score == baseline_result.confidence_score
        assert len(with_caps.probes) == 2
        assert with_caps.capabilities == {
            "dnssec_validating": True,
            "filters_detected": False,
        }

    def test_parse_capability_probes_maps_values(self) -> None:
        probes = [
            ProbeResult(ok=True, probe="capability:dnssec", details={"dnssec_validating": "true"}),
            ProbeResult(ok=True, probe="capability:ecs", details={"ecs_support": "unknown"}),
            ProbeResult(
                ok=True,
                probe="capability:filtering",
                details={
                    "filters_detected": "false",
                    "filtered_domains": "a.test.",
                },
            ),
            ProbeResult(ok=True, probe="positive:x", details={"rcode": "NOERROR"}),
        ]
        assert parse_capability_probes(probes) == {
            "dnssec_validating": True,
            "ecs_support": None,
            "filters_detected": False,
        }

    @pytest.mark.asyncio
    async def test_unknown_check_and_errors_do_not_raise(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            raise RuntimeError("boom")

        probe = await run_capability_check("does-not-exist", execute, _config())
        assert probe.ok
        assert probe.probe == "capability:does-not-exist"

    @pytest.mark.asyncio
    async def test_check_internal_error_uses_canonical_key(self) -> None:
        """An unexpected check error must still emit the canonical
        capability key (with an unknown value), not the check name."""

        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            msg = _response()
            # Remove the answer attribute to break _check_filtering internals.
            del msg.answer
            return msg

        probe = await run_capability_check(
            "filtering", execute, _config(filter_domains=["a.test."])
        )
        assert probe.ok
        assert probe.details["filters_detected"] == "unknown"
        assert "filtering" not in probe.details

    @pytest.mark.asyncio
    async def test_disabled_config_reports_unknown(self) -> None:
        async def execute(qname: str, rdtype: str, **kwargs: object) -> dns.message.Message:
            return _response(rcode=dns.rcode.SERVFAIL)

        probe = await run_capability_check("dnssec", execute, _config(enabled=False))
        assert probe.ok
        assert probe.details["dnssec_validating"] == "unknown"
