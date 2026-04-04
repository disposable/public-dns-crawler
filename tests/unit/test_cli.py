"""Unit tests for CLI argument parsing and basic command behavior."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from resolver_inventory.cli import _apply_probe_corpus_override, _build_parser, main


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
