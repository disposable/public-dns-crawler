"""Integration tests for richer external probe corpus behavior."""

from __future__ import annotations

import asyncio

import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import Corpus, CorpusEntry, build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate
from resolver_inventory.validate.scorer import score
from tests.fixtures.dns_authority import AuthoritativeDnsFixture
from tests.fixtures.dns_recursive import WrongAnswerDnsFixture, WrongNsDnsFixture

pytestmark = pytest.mark.integration


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


def _settings() -> Settings:
    settings = Settings()
    settings.validation.rounds = 1
    settings.validation.timeout_ms = 2000
    return settings


class TestExternalProbeRuntime:
    def test_imported_positive_exact_probe_is_enforced(self) -> None:
        with WrongAnswerDnsFixture() as fix:
            candidate = _udp_candidate(fix.host, fix.port)
            corpus = Corpus(
                positive=[
                    CorpusEntry(
                        qname="a.ok.test.local.",
                        rdtype="A",
                        expected_mode="exact_rrset",
                        expected_answers=["192.0.2.1"],
                        label="exact-a",
                    )
                ]
            )
            probes = asyncio.run(validate_dns_candidate(candidate, corpus, rounds=1, timeout_s=1.0))

        assert probes[0].ok is False
        assert probes[0].error == "answer_mismatch"

    def test_imported_positive_consensus_probe_is_enforced_via_baseline(self) -> None:
        with AuthoritativeDnsFixture() as baseline_fix, WrongNsDnsFixture() as candidate_fix:
            candidate = _udp_candidate(candidate_fix.host, candidate_fix.port)
            corpus = Corpus(
                positive=[
                    CorpusEntry(
                        qname="test.local.",
                        rdtype="NS",
                        expected_mode="consensus_match",
                        label="consensus-ns",
                    )
                ]
            )
            probes = asyncio.run(
                validate_dns_candidate(
                    candidate,
                    corpus,
                    rounds=1,
                    timeout_s=1.0,
                    baseline_resolvers=[f"{baseline_fix.host}:{baseline_fix.port}"],
                )
            )

        assert probes[0].ok is False
        assert probes[0].error == "answer_mismatch"

    def test_generated_corpus_file_works_with_refresh_pipeline_inputs(self) -> None:
        with AuthoritativeDnsFixture() as baseline_fix:
            settings = _settings()
            settings.validation.corpus.mode = "external"
            settings.validation.corpus.path = "tests/fixtures/probe-corpus-generated.json"
            settings.validation.corpus.schema_version = 2
            settings.validation.baseline_resolvers = [f"{baseline_fix.host}:{baseline_fix.port}"]
            candidate = _udp_candidate(baseline_fix.host, baseline_fix.port)

            corpus = build_corpus(settings.validation.corpus)
            probes = asyncio.run(
                validate_dns_candidate(
                    candidate,
                    corpus,
                    rounds=1,
                    timeout_s=1.0,
                    baseline_resolvers=settings.validation.baseline_resolvers,
                )
            )
            result = score(candidate, probes, settings)

        assert result.accepted is True
