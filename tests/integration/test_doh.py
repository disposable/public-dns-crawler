"""Integration tests for DoH validation using a local TLS fixture.

Starts a local HTTPS DoH server (via aiohttp + trustme), then validates
candidates against it. No public network is used.
"""

from __future__ import annotations

import asyncio

import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.doh import validate_doh_candidate
from resolver_inventory.validate.scorer import score
from tests.fixtures.dns_authority import ZONE_NAME
from tests.fixtures.doh_server import DOH_PATH, DoHServerFixture

pytestmark = pytest.mark.integration

CONTROLLED_ZONE = ZONE_NAME.rstrip(".")


def _make_settings(zone: str = CONTROLLED_ZONE) -> Settings:
    s = Settings()
    s.validation.corpus.mode = "controlled"
    s.validation.corpus.zone = zone
    s.validation.rounds = 1
    s.validation.timeout_ms = 5000
    return s


def _doh_candidate(host: str, port: int, url: str) -> Candidate:
    return Candidate(
        provider="LocalTest",
        source="integration-test",
        transport="doh",
        endpoint_url=url,
        host=host,
        port=port,
        path=DOH_PATH,
        tls_server_name=host,
    )


class TestGoodDoHServer:
    def test_good_doh_server_passes(self) -> None:
        with DoHServerFixture() as fix:
            candidate = _doh_candidate(fix.host, fix.port, fix.url)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_doh_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                    ssl_context=fix.client_ssl_context,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted, f"Expected accepted, got {result.status}: {result.reasons}"
        assert result.score >= settings.scoring.accept_min_score

        positive_probes = [p for p in probes if "positive" in p.probe]
        assert any(p.ok for p in positive_probes), "No passing positive probes"

        nxdomain_probes = [p for p in probes if "nxdomain" in p.probe]
        assert any(p.ok for p in nxdomain_probes), "No passing NXDOMAIN probes"


class TestDoHTlsBadHostname:
    def test_bad_tls_hostname_is_rejected(self) -> None:
        """Connect to the DoH server but present a wrong TLS server name.

        The validator's TLS probe uses the system trust store, so connecting
        to a trustme-issued cert will fail, giving us the tls_name_mismatch signal.
        """
        with DoHServerFixture() as fix:
            candidate = Candidate(
                provider=None,
                source="integration-test",
                transport="doh",
                endpoint_url=fix.url,
                host=fix.host,
                port=fix.port,
                path=DOH_PATH,
                tls_server_name="wrong-hostname.invalid",
            )
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_doh_candidate(
                    candidate,
                    corpus,
                    timeout_s=2.0,
                    rounds=1,
                )
            )
            result = score(candidate, probes, settings)

        assert not result.accepted, f"Expected rejected, got {result.status}"


class TestDoHUnreachable:
    def test_unreachable_doh_is_rejected(self) -> None:
        candidate = Candidate(
            provider=None,
            source="integration-test",
            transport="doh",
            endpoint_url="https://127.0.0.1:19998/dns-query",
            host="127.0.0.1",
            port=19998,
            path="/dns-query",
            tls_server_name="127.0.0.1",
        )
        settings = _make_settings()
        settings.validation.timeout_ms = 500
        corpus = build_corpus(settings.validation.corpus)
        probes = asyncio.run(validate_doh_candidate(candidate, corpus, timeout_s=0.5, rounds=1))
        result = score(candidate, probes, settings)
        assert not result.accepted
