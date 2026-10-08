"""Integration tests for DoT validation using a local TLS fixture.

Starts a local DNS-over-TLS server (openssl-generated self-signed cert),
then validates candidates against it. No public network is used.
"""

from __future__ import annotations

import asyncio

import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.dot import validate_dot_candidate
from resolver_inventory.validate.scorer import score
from tests.fixtures.dns_authority import ZONE_NAME
from tests.fixtures.dot_server import DoTServerFixture

pytestmark = pytest.mark.integration

CONTROLLED_ZONE = ZONE_NAME.rstrip(".")


def _make_settings(zone: str = CONTROLLED_ZONE) -> Settings:
    s = Settings()
    s.validation.corpus.mode = "controlled"
    s.validation.corpus.zone = zone
    s.validation.rounds = 1
    s.validation.timeout_ms = 5000
    s.validation.capabilities.enabled = False
    return s


def _dot_candidate(
    host: str,
    port: int,
    tls_server_name: str | None = None,
    bootstrap_ipv4: list[str] | None = None,
) -> Candidate:
    return Candidate(
        provider="LocalTest",
        source="integration-test",
        transport="dot",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
        bootstrap_ipv4=bootstrap_ipv4 or [],
        tls_server_name=tls_server_name,
    )


class TestGoodDoTServer:
    def test_good_dot_server_passes(self) -> None:
        with DoTServerFixture() as fix:
            candidate = _dot_candidate(fix.host, fix.port, tls_server_name=fix.host)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dot_candidate(
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

    def test_hostname_candidate_resolves_via_bootstrap(self) -> None:
        """Hostname DoT endpoints connect through their bootstrap IPs."""
        with DoTServerFixture() as fix:
            candidate = _dot_candidate(
                "dot.test.invalid",
                fix.port,
                bootstrap_ipv4=[fix.host],
            )
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dot_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                    ssl_context=fix.client_ssl_context,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted, f"Expected accepted, got {result.status}: {result.reasons}"

    def test_verified_ip_san_hostname_passes(self) -> None:
        """With hostname checking on, the IP SAN of the cert must match."""
        with DoTServerFixture() as fix:
            candidate = _dot_candidate(fix.host, fix.port, tls_server_name=fix.host)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dot_candidate(
                    candidate,
                    corpus,
                    timeout_s=settings.validation.timeout_ms / 1000,
                    rounds=settings.validation.rounds,
                    ssl_context=fix.verifying_client_ssl_context,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted, f"Expected accepted, got {result.status}: {result.reasons}"


class TestDoTTlsBadHostname:
    def test_bad_tls_hostname_is_rejected(self) -> None:
        """A wrong TLS server name hard-fails via tls_name_mismatch."""
        with DoTServerFixture() as fix:
            candidate = _dot_candidate(
                fix.host,
                fix.port,
                tls_server_name="wrong-hostname.invalid",
            )
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dot_candidate(
                    candidate,
                    corpus,
                    timeout_s=2.0,
                    rounds=1,
                    ssl_context=fix.verifying_client_ssl_context,
                )
            )
            result = score(candidate, probes, settings)

        assert not result.accepted, f"Expected rejected, got {result.status}"
        assert "tls_name_mismatch" in result.reasons
        assert result.score <= 59  # hard-fail cap

    def test_untrusted_cert_is_rejected(self) -> None:
        """Default CA verification rejects the self-signed fixture cert."""
        with DoTServerFixture() as fix:
            candidate = _dot_candidate(fix.host, fix.port, tls_server_name=fix.host)
            settings = _make_settings()
            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dot_candidate(
                    candidate,
                    corpus,
                    timeout_s=2.0,
                    rounds=1,
                )
            )
            result = score(candidate, probes, settings)

        assert not result.accepted, f"Expected rejected, got {result.status}"
        assert any(reason.startswith("tls_") for reason in result.reasons)


class TestDoTUnreachable:
    def test_unreachable_dot_is_rejected(self) -> None:
        candidate = _dot_candidate("127.0.0.1", 19998, tls_server_name="127.0.0.1")
        settings = _make_settings()
        settings.validation.timeout_ms = 500
        corpus = build_corpus(settings.validation.corpus)
        probes = asyncio.run(validate_dot_candidate(candidate, corpus, timeout_s=0.5, rounds=1))
        result = score(candidate, probes, settings)
        assert not result.accepted
