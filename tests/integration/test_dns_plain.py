"""Integration tests for plain DNS validation using local fixtures.

These tests start local DNS servers and verify that the validator correctly
accepts good resolvers and rejects bad ones. No public network is used.
"""

from __future__ import annotations

import asyncio

import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate
from resolver_inventory.validate.scorer import score
from tests.fixtures.dns_authority import (
    ZONE_NAME,
    AuthoritativeDnsFixture,
    AuthoritativeTcpDnsFixture,
)
from tests.fixtures.dns_recursive import SpoofingDnsFixture

pytestmark = pytest.mark.integration

CONTROLLED_ZONE = ZONE_NAME.rstrip(".")


def _make_settings(zone: str = CONTROLLED_ZONE) -> Settings:
    s = Settings()
    s.validation.corpus.mode = "controlled"
    s.validation.corpus.zone = zone
    s.validation.rounds = 1
    s.validation.timeout_ms = 2000
    return s


def _udp_candidate(host: str, port: int) -> Candidate:
    return Candidate(
        provider=None,
        source="integration-test",
        transport="dns-udp",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
    )


def _tcp_candidate(host: str, port: int) -> Candidate:
    return Candidate(
        provider=None,
        source="integration-test",
        transport="dns-tcp",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
    )


class TestGoodUdpResolver:
    def test_good_udp_resolver_passes(self) -> None:
        with AuthoritativeDnsFixture() as fix:
            candidate = _udp_candidate(fix.host, fix.port)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dns_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted, f"Expected accepted, got {result.status}: {result.reasons}"
        assert result.score >= settings.scoring.accept_min_score
        positive_probes = [p for p in probes if "positive" in p.probe]
        assert all(p.ok for p in positive_probes), [p for p in positive_probes if not p.ok]
        nxdomain_probes = [p for p in probes if "nxdomain" in p.probe]
        assert all(p.ok for p in nxdomain_probes), [p for p in nxdomain_probes if not p.ok]


class TestGoodTcpResolver:
    def test_good_tcp_resolver_passes(self) -> None:
        with AuthoritativeTcpDnsFixture() as fix:
            candidate = _tcp_candidate(fix.host, fix.port)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dns_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted, f"Expected accepted, got {result.status}: {result.reasons}"


class TestSpoofingResolver:
    def test_nxdomain_spoofing_resolver_is_rejected(self) -> None:
        with SpoofingDnsFixture() as fix:
            candidate = _udp_candidate(fix.host, fix.port)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dns_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                )
            )
            result = score(candidate, probes, settings)

        assert not result.accepted, f"Expected rejected, got {result.status}"
        assert "nxdomain_spoofing" in result.reasons


class TestUnreachableResolver:
    def test_unreachable_resolver_is_rejected(self) -> None:
        candidate = _udp_candidate("127.0.0.1", 19999)
        settings = _make_settings()
        settings.validation.timeout_ms = 500
        corpus = build_corpus(settings.validation.corpus)
        probes = asyncio.run(
            validate_dns_candidate(
                candidate,
                corpus,
                timeout_s=0.5,
                rounds=1,
            )
        )
        result = score(candidate, probes, settings)
        assert not result.accepted
