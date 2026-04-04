"""Integration tests for generation-time probe corpus hardening."""

from __future__ import annotations

import pytest

from resolver_inventory.probe_corpus.generator import generate_probe_corpus
from resolver_inventory.probe_corpus.sources import parse_seed_snapshot
from resolver_inventory.probe_corpus.validators import UdpBaselineResolverClient
from resolver_inventory.settings import ProbeCorpusConfig
from tests.fixtures.dns_authority import AuthoritativeDnsFixture
from tests.fixtures.dns_recursive import SpoofingDnsFixture, WrongNsDnsFixture

pytestmark = pytest.mark.integration


def _seed_snapshot() -> object:
    return {
        "snapshot_version": 1,
        "generated_at": "2026-04-04T00:00:00Z",
        "sources_used": ["integration-test-seeds"],
        "root_servers": [],
        "delegations": [
            {
                "zone": "test.local.",
                "nameservers": ["ns.test.local."],
                "source": "integration-zone",
                "exact_hosts": [
                    {
                        "hostname": "a.ok.test.local.",
                        "ipv4": ["192.0.2.1"],
                        "source": "integration-zone",
                        "operator_family": "test-local",
                    }
                ],
            }
        ],
    }


def _config(resolvers: list[str]) -> ProbeCorpusConfig:
    config = ProbeCorpusConfig()
    config.baseline.resolvers = resolvers
    config.negative.parent_zones = ["test.local."]
    config.validation.exact.rounds = 1
    config.validation.exact.required_quorum = 2
    config.validation.consensus.rounds = 1
    config.validation.consensus.required_quorum = 2
    config.validation.negative.rounds = 1
    config.validation.negative.labels_per_parent = 2
    config.validation.negative.required_quorum = 2
    config.validation.negative.label_length = 8
    config.thresholds.min_positive_exact = 1
    config.thresholds.min_positive_consensus = 1
    config.thresholds.min_negative_generated = 1
    return config


class TestProbeCorpusGeneration:
    def test_generation_accepts_locally_validated_probes(self) -> None:
        with AuthoritativeDnsFixture() as fix:
            resolvers = [
                f"{fix.host}:{fix.port}",
                f"{fix.host}:{fix.port}",
                f"{fix.host}:{fix.port}",
            ]
            result = generate_probe_corpus(
                _config(resolvers),
                parse_seed_snapshot(_seed_snapshot()),
                client=UdpBaselineResolverClient(timeout_s=1.0),
            )

        assert result.report.accepted_counts["positive_exact"] == 1
        assert result.report.accepted_counts["positive_consensus"] == 1
        assert result.report.accepted_counts["negative_generated"] == 1

    def test_generation_rejects_consensus_when_baseline_disagrees(self) -> None:
        with AuthoritativeDnsFixture() as good_fix, WrongNsDnsFixture() as bad_fix:
            resolvers = [
                f"{good_fix.host}:{good_fix.port}",
                f"{good_fix.host}:{good_fix.port}",
                f"{bad_fix.host}:{bad_fix.port}",
            ]
            config = _config(resolvers)
            config.thresholds.min_positive_exact = 0
            config.thresholds.min_negative_generated = 0
            with pytest.raises(ValueError, match="min_positive_consensus"):
                generate_probe_corpus(
                    config,
                    parse_seed_snapshot(_seed_snapshot()),
                    client=UdpBaselineResolverClient(timeout_s=1.0),
                )

    def test_generation_rejects_wildcard_like_negative_parent(self) -> None:
        with AuthoritativeDnsFixture() as good_fix, SpoofingDnsFixture() as spoof_fix:
            config = _config(
                [
                    f"{good_fix.host}:{good_fix.port}",
                    f"{good_fix.host}:{good_fix.port}",
                    f"{spoof_fix.host}:{spoof_fix.port}",
                ]
            )
            config.thresholds.min_positive_exact = 0
            config.thresholds.min_positive_consensus = 0
            config.thresholds.min_negative_generated = 0

            result = generate_probe_corpus(
                config,
                parse_seed_snapshot(_seed_snapshot()),
                client=UdpBaselineResolverClient(timeout_s=1.0),
            )

        assert result.report.rejected_by_reason["negative_parent_wildcard_like"] == 1
