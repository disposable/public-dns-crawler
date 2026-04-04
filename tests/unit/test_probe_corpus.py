"""Unit tests for probe corpus generation and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from resolver_inventory.probe_corpus.generator import generate_probe_corpus
from resolver_inventory.probe_corpus.schema import ProbeSchemaError, parse_probe_corpus
from resolver_inventory.probe_corpus.sources import parse_seed_snapshot
from resolver_inventory.probe_corpus.validators import (
    generate_negative_qname,
    validate_negative_parent_zone,
)
from resolver_inventory.settings import ProbeCorpusConfig
from resolver_inventory.validate.corpus import CorpusEntry

FIXTURES = Path("tests/fixtures")


def _seed_snapshot() -> object:
    return {
        "snapshot_version": 1,
        "generated_at": "2026-04-04T00:00:00Z",
        "sources_used": ["unit-test-seeds"],
        "root_servers": [
            {
                "hostname": "a.root-servers.net.",
                "ipv4": ["198.41.0.4"],
                "ipv6": ["2001:503:ba3e::2:30"],
                "source": "seed-root",
                "operator_family": "root-a",
            }
        ],
        "delegations": [
            {
                "zone": "de.",
                "nameservers": ["a.nic.de.", "f.nic.de.", "z.nic.de."],
                "source": "seed-de",
                "exact_hosts": [
                    {
                        "hostname": "a.nic.de.",
                        "ipv4": ["194.0.0.53"],
                        "source": "seed-de",
                        "operator_family": "denic",
                    }
                ],
            },
            {
                "zone": "jp.",
                "nameservers": ["a.dns.jp.", "b.dns.jp.", "h.dns.jp."],
                "source": "seed-jp",
                "exact_hosts": [
                    {
                        "hostname": "a.dns.jp.",
                        "ipv4": ["203.119.1.1"],
                        "source": "seed-jp",
                        "operator_family": "jprs",
                    }
                ],
            },
        ],
    }


class TestProbeCorpusSchema:
    def test_parse_richer_probe_corpus_schema(self) -> None:
        raw = FIXTURES.joinpath("probe-corpus-generated.json").read_text(encoding="utf-8")
        corpus = parse_probe_corpus(__import__("json").loads(raw), required_schema_version=2)
        assert corpus.generator_version == "0.1.0"
        assert corpus.probe_counts["positive_consensus"] == 1

    def test_reject_missing_schema_version(self) -> None:
        with pytest.raises(ProbeSchemaError, match="schema_version"):
            parse_probe_corpus({"corpus_version": "x", "generated_at": "y", "probes": []})


class TestProbeGeneration:
    def test_generate_positive_exact_probes_from_seed_data(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "resolver_inventory.probe_corpus.generator.validate_negative_parent_zone",
            lambda **kwargs: True,
        )
        config = ProbeCorpusConfig()
        config.baseline.resolvers = ["127.0.0.1:53"]
        config.negative.parent_zones = ["com."]
        config.min_exact_probes = 2
        config.min_consensus_probes = 2
        config.min_negative_parents = 1

        corpus = generate_probe_corpus(config, parse_seed_snapshot(_seed_snapshot()))

        exact = [probe for probe in corpus.probes if probe.kind == "positive_exact"]
        assert any(probe.qname == "a.root-servers.net." and probe.qtype == "A" for probe in exact)
        assert any(probe.qname == "a.nic.de." and probe.qtype == "A" for probe in exact)

    def test_generate_positive_consensus_probes_from_seed_data(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "resolver_inventory.probe_corpus.generator.validate_negative_parent_zone",
            lambda **kwargs: True,
        )
        config = ProbeCorpusConfig()
        config.baseline.resolvers = ["127.0.0.1:53"]
        config.negative.parent_zones = ["com."]
        config.min_exact_probes = 2
        config.min_consensus_probes = 2
        config.min_negative_parents = 1

        corpus = generate_probe_corpus(config, parse_seed_snapshot(_seed_snapshot()))

        consensus = [probe for probe in corpus.probes if probe.kind == "positive_consensus"]
        assert any(probe.qname == "de." and probe.qtype == "NS" for probe in consensus)
        assert any(probe.qname == "jp." and probe.qtype == "NS" for probe in consensus)

    def test_generate_negative_templates_from_parent_zones(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(
            "resolver_inventory.probe_corpus.generator.validate_negative_parent_zone",
            lambda **kwargs: True,
        )
        config = ProbeCorpusConfig()
        config.baseline.resolvers = ["127.0.0.1:53"]
        config.negative.parent_zones = ["com.", "net."]
        config.min_exact_probes = 2
        config.min_consensus_probes = 2
        config.min_negative_parents = 2

        corpus = generate_probe_corpus(config, parse_seed_snapshot(_seed_snapshot()))

        negative = [probe for probe in corpus.probes if probe.kind == "negative_generated"]
        assert {probe.parent_zone for probe in negative} == {"com.", "net."}
        assert all(
            probe.qname_template == "{uuid}." + probe.parent_zone.rstrip(".") + "."
            for probe in negative
        )


class TestNegativeValidation:
    def test_runtime_template_expansion(self) -> None:
        entry = CorpusEntry(qname_template="{uuid}.com.", rdtype="A")
        first = entry.render_qname()
        second = entry.render_qname()
        assert first.endswith(".com.")
        assert second.endswith(".com.")
        assert first != second

    def test_negative_parent_zone_rejection_on_wildcard_like_behavior(self) -> None:
        attempts = {"count": 0}

        async def fake_query(resolver: str, qname: str) -> str:
            attempts["count"] += 1
            return "NOERROR" if attempts["count"] == 2 else "NXDOMAIN"

        assert not validate_negative_parent_zone(
            parent_zone="com.",
            resolvers=["127.0.0.1:53"],
            validation_rounds=3,
            query_fn=fake_query,
        )

    def test_generate_negative_qname_uses_requested_length(self) -> None:
        qname = generate_negative_qname("de.", label_length=40)
        assert qname.endswith(".de.")
        assert len(qname.split(".")[0]) == 40
