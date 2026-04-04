"""Unit tests for corpus loading and dispatch."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from resolver_inventory.settings import CorpusConfig
from resolver_inventory.validate.corpus import (
    build_builtin_fallback_corpus,
    build_controlled_corpus,
    build_corpus,
    load_external_corpus,
)
from resolver_inventory.validate.corpus_schema import CorpusSchemaError

FIXTURES = Path("tests/fixtures")


class TestExternalCorpusLoading:
    def test_parse_valid_corpus_file(self) -> None:
        corpus = load_external_corpus(
            FIXTURES / "probe-corpus-valid.json",
            required_schema_version=1,
            strict=True,
        )
        assert corpus.mode == "external"
        assert len(corpus.positive) == 1
        assert len(corpus.nxdomain) == 1

    def test_reject_missing_schema_version(self) -> None:
        with pytest.raises(CorpusSchemaError, match="schema_version"):
            load_external_corpus(
                FIXTURES / "probe-corpus-invalid-schema.json",
                required_schema_version=1,
                strict=True,
            )

    def test_reject_unsupported_schema_version(self) -> None:
        with pytest.raises(CorpusSchemaError, match="unsupported schema_version"):
            load_external_corpus(
                FIXTURES / "probe-corpus-valid.json",
                required_schema_version=2,
                strict=True,
            )

    def test_reject_probe_without_qname_or_template(self, tmp_path: Path) -> None:
        path = tmp_path / "missing-qname.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "corpus_version": "broken",
                    "generated_at": "2026-04-04T00:00:00Z",
                    "probes": [
                        {
                            "id": "bad-probe",
                            "kind": "negative_generated",
                            "qtype": "A",
                            "expected_mode": "nxdomain",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        with pytest.raises(CorpusSchemaError, match="qname"):
            load_external_corpus(path, required_schema_version=1, strict=True)


class TestBuildCorpusDispatch:
    def test_dispatch_controlled(self) -> None:
        corpus = build_corpus(CorpusConfig(mode="controlled", zone="test.local"))
        expected = build_controlled_corpus("test.local")
        assert corpus.mode == expected.mode
        assert len(corpus.positive) == len(expected.positive)

    def test_dispatch_fallback(self) -> None:
        corpus = build_corpus(CorpusConfig(mode="fallback"))
        expected = build_builtin_fallback_corpus()
        assert corpus.mode == expected.mode
        assert len(corpus.nxdomain) == len(expected.nxdomain)

    def test_dispatch_external(self) -> None:
        corpus = build_corpus(
            CorpusConfig(
                mode="external",
                path=str(FIXTURES / "probe-corpus-valid.json"),
                schema_version=1,
            )
        )
        assert corpus.mode == "external"
        assert len(corpus.positive) == 1

    def test_external_fallback_requires_opt_in(self) -> None:
        with pytest.raises(CorpusSchemaError):
            build_corpus(
                CorpusConfig(
                    mode="external",
                    path=str(FIXTURES / "probe-corpus-invalid-schema.json"),
                    schema_version=1,
                )
            )

    def test_external_fallback_used_only_when_enabled(self) -> None:
        corpus = build_corpus(
            CorpusConfig(
                mode="external",
                path=str(FIXTURES / "probe-corpus-invalid-schema.json"),
                schema_version=1,
                allow_builtin_fallback=True,
            )
        )
        assert corpus.mode == "fallback"
