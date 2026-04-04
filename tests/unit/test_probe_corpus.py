"""Unit tests for probe corpus generation hardening."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resolver_inventory.probe_corpus.generator import generate_probe_corpus
from resolver_inventory.probe_corpus.schema import (
    ProbeDefinition,
    ProbeSchemaError,
    parse_probe_corpus,
)
from resolver_inventory.probe_corpus.sources import parse_seed_snapshot
from resolver_inventory.probe_corpus.validators import (
    BaselineQueryResult,
    validate_negative_parent_zone,
    validate_positive_consensus_probe,
    validate_positive_exact_probe,
)
from resolver_inventory.settings import ProbeCorpusConfig
from resolver_inventory.validate.corpus import CorpusEntry

FIXTURES = Path("tests/fixtures")


class FakeBaselineClient:
    def __init__(self, responses: dict[tuple[str, str, str], list[BaselineQueryResult]]) -> None:
        self._responses = {key: list(value) for key, value in responses.items()}

    async def query(self, resolver: str, qname: str, qtype: str) -> BaselineQueryResult:
        key = (resolver, qname, qtype)
        queue = self._responses.get(key, [])
        if queue:
            return queue.pop(0)
        return BaselineQueryResult(resolver=resolver, qname=qname, qtype=qtype, rcode="ERROR")


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


def _config() -> ProbeCorpusConfig:
    config = ProbeCorpusConfig()
    config.baseline.resolvers = ["r1", "r2", "r3"]
    config.negative.parent_zones = ["com.", "net."]
    config.validation.exact.rounds = 1
    config.validation.exact.required_quorum = 2
    config.validation.consensus.rounds = 1
    config.validation.consensus.required_quorum = 2
    config.validation.negative.rounds = 2
    config.validation.negative.labels_per_parent = 2
    config.validation.negative.required_quorum = 2
    config.validation.negative.label_length = 8
    config.thresholds.min_positive_exact = 2
    config.thresholds.min_positive_consensus = 2
    config.thresholds.min_negative_generated = 2
    return config


class TestProbeCorpusSchema:
    def test_parse_richer_probe_corpus_schema(self) -> None:
        raw = FIXTURES.joinpath("probe-corpus-generated.json").read_text(encoding="utf-8")
        corpus = parse_probe_corpus(json.loads(raw), required_schema_version=2)
        assert corpus.generator_version == "0.1.0"
        assert corpus.probe_counts["positive_consensus"] == 1

    def test_reject_missing_schema_version(self) -> None:
        with pytest.raises(ProbeSchemaError, match="schema_version"):
            parse_probe_corpus({"corpus_version": "x", "generated_at": "y", "probes": []})


class TestPositiveExactValidation:
    def test_accepts_exact_rrset_match(self) -> None:
        probe = ProbeDefinition(
            id="exact-a",
            kind="positive_exact",
            qname="a.nic.de.",
            qtype="A",
            expected_mode="exact_rrset",
            expected_answers=["194.0.0.53"],
        )
        client = FakeBaselineClient(
            {
                ("r1", "a.nic.de.", "A"): [
                    BaselineQueryResult("r1", "a.nic.de.", "A", "NOERROR", ["194.0.0.53"])
                ],
                ("r2", "a.nic.de.", "A"): [
                    BaselineQueryResult("r2", "a.nic.de.", "A", "NOERROR", ["194.0.0.53"])
                ],
                ("r3", "a.nic.de.", "A"): [
                    BaselineQueryResult("r3", "a.nic.de.", "A", "ERROR", error="timeout")
                ],
            }
        )

        validation = validate_positive_exact_probe(probe, _config(), client)

        assert validation.accepted is True
        assert validation.agreed_answers == ["194.0.0.53"]

    def test_rejects_exact_rrset_mismatch(self) -> None:
        probe = ProbeDefinition(
            id="exact-a",
            kind="positive_exact",
            qname="a.nic.de.",
            qtype="A",
            expected_mode="exact_rrset",
            expected_answers=["194.0.0.53"],
        )
        client = FakeBaselineClient(
            {
                ("r1", "a.nic.de.", "A"): [
                    BaselineQueryResult("r1", "a.nic.de.", "A", "NOERROR", ["10.0.0.1"])
                ],
                ("r2", "a.nic.de.", "A"): [
                    BaselineQueryResult("r2", "a.nic.de.", "A", "NOERROR", ["194.0.0.53"])
                ],
                ("r3", "a.nic.de.", "A"): [
                    BaselineQueryResult("r3", "a.nic.de.", "A", "NOERROR", ["194.0.0.53"])
                ],
            }
        )

        validation = validate_positive_exact_probe(probe, _config(), client)

        assert validation.accepted is False
        assert validation.rejection_reason == "exact_rrset_mismatch"


class TestPositiveConsensusValidation:
    def test_accepts_consensus_quorum(self) -> None:
        probe = ProbeDefinition(
            id="ns-de",
            kind="positive_consensus",
            qname="de.",
            qtype="NS",
            expected_mode="consensus_match",
        )
        client = FakeBaselineClient(
            {
                ("r1", "de.", "NS"): [
                    BaselineQueryResult("r1", "de.", "NS", "NOERROR", ["a.nic.de.", "f.nic.de."])
                ],
                ("r2", "de.", "NS"): [
                    BaselineQueryResult("r2", "de.", "NS", "NOERROR", ["f.nic.de.", "a.nic.de."])
                ],
                ("r3", "de.", "NS"): [
                    BaselineQueryResult("r3", "de.", "NS", "ERROR", error="timeout")
                ],
            }
        )

        validation = validate_positive_consensus_probe(probe, _config(), client)

        assert validation.accepted is True
        assert validation.agreed_nameservers == ["a.nic.de.", "f.nic.de."]

    def test_rejects_consensus_disagreement(self) -> None:
        probe = ProbeDefinition(
            id="ns-de",
            kind="positive_consensus",
            qname="de.",
            qtype="NS",
            expected_mode="consensus_match",
        )
        client = FakeBaselineClient(
            {
                ("r1", "de.", "NS"): [
                    BaselineQueryResult("r1", "de.", "NS", "NOERROR", ["a.nic.de."])
                ],
                ("r2", "de.", "NS"): [
                    BaselineQueryResult("r2", "de.", "NS", "NOERROR", ["f.nic.de."])
                ],
                ("r3", "de.", "NS"): [
                    BaselineQueryResult("r3", "de.", "NS", "NOERROR", ["z.nic.de."])
                ],
            }
        )

        validation = validate_positive_consensus_probe(probe, _config(), client)

        assert validation.accepted is False
        assert validation.rejection_reason == "insufficient_baseline_consensus"

    def test_rejects_consensus_baseline_disagreement(self) -> None:
        probe = ProbeDefinition(
            id="ns-de",
            kind="positive_consensus",
            qname="de.",
            qtype="NS",
            expected_mode="consensus_match",
        )
        client = FakeBaselineClient(
            {
                ("r1", "de.", "NS"): [
                    BaselineQueryResult("r1", "de.", "NS", "NOERROR", ["a.nic.de."])
                ],
                ("r2", "de.", "NS"): [
                    BaselineQueryResult("r2", "de.", "NS", "NOERROR", ["a.nic.de."])
                ],
                ("r3", "de.", "NS"): [
                    BaselineQueryResult("r3", "de.", "NS", "NOERROR", ["z.nic.de."])
                ],
            }
        )

        validation = validate_positive_consensus_probe(probe, _config(), client)

        assert validation.accepted is False
        assert validation.rejection_reason == "baseline_disagreement"


class TestNegativeValidation:
    def test_runtime_template_expansion(self) -> None:
        entry = CorpusEntry(qname_template="{uuid}.com.", rdtype="A")
        first = entry.render_qname()
        second = entry.render_qname()
        assert first.endswith(".com.")
        assert second.endswith(".com.")
        assert first != second

    def test_negative_parent_accepts_repeated_nxdomain(self) -> None:
        config = _config()
        config.negative.parent_zones = ["com."]
        client = FakeBaselineClient(
            {
                ("r1", "aaaaaaaa.com.", "A"): [
                    BaselineQueryResult("r1", "aaaaaaaa.com.", "A", "NXDOMAIN")
                ],
                ("r2", "aaaaaaaa.com.", "A"): [
                    BaselineQueryResult("r2", "aaaaaaaa.com.", "A", "NXDOMAIN")
                ],
                ("r3", "aaaaaaaa.com.", "A"): [
                    BaselineQueryResult("r3", "aaaaaaaa.com.", "A", "ERROR", error="timeout")
                ],
                ("r1", "bbbbbbbb.com.", "A"): [
                    BaselineQueryResult("r1", "bbbbbbbb.com.", "A", "NXDOMAIN")
                ],
                ("r2", "bbbbbbbb.com.", "A"): [
                    BaselineQueryResult("r2", "bbbbbbbb.com.", "A", "NXDOMAIN")
                ],
                ("r3", "bbbbbbbb.com.", "A"): [
                    BaselineQueryResult("r3", "bbbbbbbb.com.", "A", "ERROR", error="timeout")
                ],
                ("r1", "cccccccc.com.", "A"): [
                    BaselineQueryResult("r1", "cccccccc.com.", "A", "NXDOMAIN")
                ],
                ("r2", "cccccccc.com.", "A"): [
                    BaselineQueryResult("r2", "cccccccc.com.", "A", "NXDOMAIN")
                ],
                ("r3", "cccccccc.com.", "A"): [
                    BaselineQueryResult("r3", "cccccccc.com.", "A", "ERROR", error="timeout")
                ],
                ("r1", "dddddddd.com.", "A"): [
                    BaselineQueryResult("r1", "dddddddd.com.", "A", "NXDOMAIN")
                ],
                ("r2", "dddddddd.com.", "A"): [
                    BaselineQueryResult("r2", "dddddddd.com.", "A", "NXDOMAIN")
                ],
                ("r3", "dddddddd.com.", "A"): [
                    BaselineQueryResult("r3", "dddddddd.com.", "A", "ERROR", error="timeout")
                ],
            }
        )
        labels = iter(["aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"])

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                "resolver_inventory.probe_corpus.validators.generate_negative_qname",
                lambda parent_zone, label_length=40: f"{next(labels)}.{parent_zone.rstrip('.')}.",
            )
            validation = validate_negative_parent_zone(
                parent_zone="com.",
                config=config,
                client=client,
            )

        assert validation.accepted is True

    def test_negative_parent_rejects_wildcard_like_behavior(self) -> None:
        config = _config()
        client = FakeBaselineClient(
            {
                ("r1", "aaaaaaaa.com.", "A"): [
                    BaselineQueryResult("r1", "aaaaaaaa.com.", "A", "NOERROR", ["192.0.2.9"])
                ],
                ("r2", "aaaaaaaa.com.", "A"): [
                    BaselineQueryResult("r2", "aaaaaaaa.com.", "A", "NXDOMAIN")
                ],
            }
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                "resolver_inventory.probe_corpus.validators.generate_negative_qname",
                lambda parent_zone, label_length=40: "aaaaaaaa.com.",
            )
            validation = validate_negative_parent_zone(
                parent_zone="com.",
                config=config,
                client=client,
            )

        assert validation.accepted is False
        assert validation.rejection_reason == "negative_parent_wildcard_like"


class TestGenerationPipeline:
    def test_rejection_reason_tracking_and_threshold_failure(self) -> None:
        config = _config()
        config.thresholds.min_positive_exact = 3
        client = FakeBaselineClient({})

        with pytest.raises(ValueError, match="min_positive_exact"):
            generate_probe_corpus(config, parse_seed_snapshot(_seed_snapshot()), client=client)

    def test_generator_records_rejected_reasons(self) -> None:
        config = _config()
        config.thresholds.min_positive_exact = 0
        config.thresholds.min_positive_consensus = 0
        config.thresholds.min_negative_generated = 0

        responses: dict[tuple[str, str, str], list[BaselineQueryResult]] = {
            ("r1", "a.root-servers.net.", "A"): [
                BaselineQueryResult("r1", "a.root-servers.net.", "A", "NOERROR", ["198.41.0.4"])
            ],
            ("r2", "a.root-servers.net.", "A"): [
                BaselineQueryResult("r2", "a.root-servers.net.", "A", "NOERROR", ["198.41.0.4"])
            ],
            ("r3", "a.root-servers.net.", "A"): [
                BaselineQueryResult("r3", "a.root-servers.net.", "A", "ERROR", error="timeout")
            ],
            ("r1", "a.root-servers.net.", "AAAA"): [
                BaselineQueryResult(
                    "r1",
                    "a.root-servers.net.",
                    "AAAA",
                    "NOERROR",
                    ["2001:503:ba3e::2:30"],
                )
            ],
            ("r2", "a.root-servers.net.", "AAAA"): [
                BaselineQueryResult(
                    "r2",
                    "a.root-servers.net.",
                    "AAAA",
                    "NOERROR",
                    ["2001:503:ba3e::2:30"],
                )
            ],
            ("r3", "a.root-servers.net.", "AAAA"): [
                BaselineQueryResult("r3", "a.root-servers.net.", "AAAA", "ERROR", error="timeout")
            ],
            ("r1", "a.nic.de.", "A"): [
                BaselineQueryResult("r1", "a.nic.de.", "A", "NOERROR", ["10.0.0.1"])
            ],
            ("r2", "a.nic.de.", "A"): [
                BaselineQueryResult("r2", "a.nic.de.", "A", "NOERROR", ["10.0.0.1"])
            ],
            ("r3", "a.nic.de.", "A"): [
                BaselineQueryResult("r3", "a.nic.de.", "A", "NOERROR", ["10.0.0.1"])
            ],
            ("r1", "a.dns.jp.", "A"): [
                BaselineQueryResult("r1", "a.dns.jp.", "A", "ERROR", error="timeout")
            ],
            ("r2", "a.dns.jp.", "A"): [
                BaselineQueryResult("r2", "a.dns.jp.", "A", "ERROR", error="timeout")
            ],
            ("r3", "a.dns.jp.", "A"): [
                BaselineQueryResult("r3", "a.dns.jp.", "A", "ERROR", error="timeout")
            ],
            ("r1", "de.", "NS"): [
                BaselineQueryResult("r1", "de.", "NS", "NOERROR", ["a.nic.de.", "f.nic.de."])
            ],
            ("r2", "de.", "NS"): [
                BaselineQueryResult("r2", "de.", "NS", "NOERROR", ["a.nic.de.", "f.nic.de."])
            ],
            ("r3", "de.", "NS"): [BaselineQueryResult("r3", "de.", "NS", "ERROR", error="timeout")],
            ("r1", "jp.", "NS"): [BaselineQueryResult("r1", "jp.", "NS", "NOERROR", ["a.dns.jp."])],
            ("r2", "jp.", "NS"): [BaselineQueryResult("r2", "jp.", "NS", "NOERROR", ["b.dns.jp."])],
            ("r3", "jp.", "NS"): [BaselineQueryResult("r3", "jp.", "NS", "NOERROR", ["h.dns.jp."])],
        }
        for qname in ["aaaaaaaa.com.", "bbbbbbbb.com.", "cccccccc.com.", "dddddddd.com."]:
            responses[("r1", qname, "A")] = [BaselineQueryResult("r1", qname, "A", "NXDOMAIN")]
            responses[("r2", qname, "A")] = [BaselineQueryResult("r2", qname, "A", "NXDOMAIN")]
            responses[("r3", qname, "A")] = [
                BaselineQueryResult("r3", qname, "A", "ERROR", error="timeout")
            ]
        for qname in ["eeeeeeee.net.", "ffffffff.net.", "gggggggg.net.", "hhhhhhhh.net."]:
            responses[("r1", qname, "A")] = [
                BaselineQueryResult("r1", qname, "A", "NOERROR", ["192.0.2.9"])
            ]
            responses[("r2", qname, "A")] = [BaselineQueryResult("r2", qname, "A", "NXDOMAIN")]
            responses[("r3", qname, "A")] = [
                BaselineQueryResult("r3", qname, "A", "ERROR", error="timeout")
            ]

        client = FakeBaselineClient(responses)
        labels = iter(
            [
                "aaaaaaaa",
                "bbbbbbbb",
                "cccccccc",
                "dddddddd",
                "eeeeeeee",
                "ffffffff",
                "gggggggg",
                "hhhhhhhh",
            ]
        )
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(
                "resolver_inventory.probe_corpus.validators.generate_negative_qname",
                lambda parent_zone, label_length=40: f"{next(labels)}.{parent_zone.rstrip('.')}.",
            )
            result = generate_probe_corpus(
                config,
                parse_seed_snapshot(_seed_snapshot()),
                client=client,
            )

        assert result.report.accepted_count > 0
        assert result.report.rejected_by_reason["exact_rrset_mismatch"] >= 1
        assert result.report.rejected_by_reason["timeout_rate_high"] >= 1
        assert result.report.rejected_by_reason["insufficient_baseline_consensus"] >= 1
        assert result.report.rejected_by_reason["negative_parent_wildcard_like"] >= 1
