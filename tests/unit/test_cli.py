"""Unit tests for CLI argument parsing and basic command behavior."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from resolver_inventory.cli import (
    _apply_probe_corpus_override,
    _build_parser,
    cmd_generate_probe_corpus,
    main,
)
from resolver_inventory.probe_corpus.models import GeneratedProbeCorpusResult, ProbeGenerationReport
from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition


class TestCliParser:
    def test_discover_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["discover"])
        assert args.command == "discover"
        assert args.output is None

    def test_discover_with_output(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["discover", "--output", "out.json"])
        assert args.output == "out.json"

    def test_validate_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["validate"])
        assert args.command == "validate"

    def test_refresh_accepts_probe_corpus_override(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            [
                "refresh",
                "--config",
                "configs/default.toml",
                "--probe-corpus",
                "tests/fixtures/x.json",
            ]
        )
        assert args.config == "configs/default.toml"
        assert args.probe_corpus == "tests/fixtures/x.json"

    def test_export_requires_format(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["export"])

    def test_export_json(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["export", "json"])
        assert args.format == "json"

    def test_export_dnsdist(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["export", "dnsdist"])
        assert args.format == "dnsdist"

    def test_export_unbound(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["export", "unbound"])
        assert args.format == "unbound"

    def test_no_subcommand_exits(self) -> None:
        with pytest.raises(SystemExit):
            main([])

    def test_log_level_default(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["discover"])
        assert args.log_level == "INFO"

    def test_log_level_debug(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--log-level", "DEBUG", "discover"])
        assert args.log_level == "DEBUG"

    def test_validate_probe_corpus_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            ["validate-probe-corpus", "--input", "tests/fixtures/probe-corpus-valid.json"]
        )
        assert args.command == "validate-probe-corpus"
        assert args.schema_version == 1

    def test_generate_probe_corpus_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["generate-probe-corpus", "--output", "outputs/probe-corpus"])
        assert args.command == "generate-probe-corpus"
        assert args.output == "outputs/probe-corpus"


class TestCliProbeCorpusOverride:
    def test_apply_probe_corpus_override_forces_external_mode(self) -> None:
        from resolver_inventory.settings import Settings

        args = argparse.Namespace(probe_corpus="tests/fixtures/probe-corpus-valid.json")
        settings = Settings()
        settings.validation.corpus.mode = "controlled"
        _apply_probe_corpus_override(args, settings)
        assert settings.validation.corpus.mode == "external"
        assert settings.validation.corpus.path == "tests/fixtures/probe-corpus-valid.json"


class TestCliExport:
    def _make_validated_json(self, tmp_path: Path) -> Path:
        data = [
            {
                "status": "accepted",
                "score": 90,
                "accepted": True,
                "reasons": [],
                "candidate": {
                    "provider": None,
                    "source": "test",
                    "transport": "dns-udp",
                    "endpoint_url": None,
                    "host": "192.0.2.1",
                    "port": 53,
                    "path": None,
                    "bootstrap_ipv4": [],
                    "bootstrap_ipv6": [],
                    "tls_server_name": None,
                    "metadata": {},
                },
                "probes": [],
            }
        ]
        p = tmp_path / "validated.json"
        p.write_text(json.dumps(data))
        return p

    def test_export_json_to_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        in_file = self._make_validated_json(tmp_path)
        with pytest.raises(SystemExit) as exc:
            main(["export", "json", "--input", str(in_file)])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 1

    def test_export_text_to_stdout(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        in_file = self._make_validated_json(tmp_path)
        with pytest.raises(SystemExit) as exc:
            main(["export", "text", "--input", str(in_file)])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "192.0.2.1:53" in out

    def test_export_missing_input_fails(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["export", "json", "--input", str(tmp_path / "nonexistent.json")])
        assert exc.value.code == 1


class TestGenerateProbeCorpusCommand:
    def test_generate_probe_corpus_writes_outputs(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = tmp_path / "probe-corpus.toml"
        config.write_text(
            "\n".join(
                [
                    "[probe_corpus]",
                    'seed_path = "configs/probe-corpus-seeds.json"',
                    "",
                    "[probe_corpus.baseline]",
                    'resolvers = ["127.0.0.1:53"]',
                    "",
                    "[probe_corpus.negative]",
                    'parent_zones = ["com."]',
                    "label_length = 40",
                    "validation_rounds = 1",
                    "",
                    "[probe_corpus.thresholds]",
                    "min_positive_exact = 1",
                    "min_positive_consensus = 1",
                    "min_negative_generated = 1",
                ]
            ),
            encoding="utf-8",
        )
        fake_result = GeneratedProbeCorpusResult(
            corpus=ProbeCorpus(
                schema_version=2,
                corpus_version="test",
                generated_at="2026-04-04T00:00:00Z",
                generator_version="0.1.0",
                sources_used=["unit-test"],
                probe_counts={
                    "positive_exact": 1,
                    "positive_consensus": 1,
                    "negative_generated": 1,
                },
                probes=[
                    ProbeDefinition(
                        id="probe-a",
                        kind="positive_exact",
                        qname="example.com.",
                        qtype="A",
                        expected_mode="exact_rrset",
                        expected_answers=["192.0.2.1"],
                    )
                ],
            ),
            report=ProbeGenerationReport(
                total_candidates=3,
                accepted_count=3,
                rejected_count=0,
                candidate_counts={
                    "positive_exact": 1,
                    "positive_consensus": 1,
                    "negative_generated": 1,
                },
                accepted_counts={
                    "positive_exact": 1,
                    "positive_consensus": 1,
                    "negative_generated": 1,
                },
                baseline_resolvers_used=["127.0.0.1:53"],
            ),
        )
        monkeypatch.setattr(
            "resolver_inventory.probe_corpus.generator.generate_probe_corpus",
            lambda config, seed_snapshot: fake_result,
        )

        rc = cmd_generate_probe_corpus(
            argparse.Namespace(
                config=str(config),
                seed_file=None,
                output=str(tmp_path / "out"),
            )
        )

        assert rc == 0
        assert (tmp_path / "out" / "probe-corpus.json").exists()
        assert (tmp_path / "out" / "probe-corpus.yaml").exists()
        assert (tmp_path / "out" / "metadata.json").exists()
        assert (tmp_path / "out" / "SUMMARY.md").exists()
