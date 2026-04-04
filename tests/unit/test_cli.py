"""Unit tests for CLI argument parsing and basic command behavior."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from resolver_inventory.cli import (
    _apply_probe_corpus_override,
    _build_parser,
    _ValidateProgressReporter,
    cmd_generate_probe_corpus,
    cmd_materialize_results,
    cmd_split_candidates,
    main,
)
from resolver_inventory.models import Candidate, ValidationResult
from resolver_inventory.probe_corpus.models import GeneratedProbeCorpusResult, ProbeGenerationReport
from resolver_inventory.probe_corpus.schema import ProbeCorpus, ProbeDefinition
from resolver_inventory.validate import ValidationProgress


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

    def test_discover_with_filtered_output(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["discover", "--filtered-output", "filtered.json"])
        assert args.filtered_output == "filtered.json"

    def test_validate_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["validate"])
        assert args.command == "validate"

    def test_validate_parallelism_override(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["validate", "--validation-parallelism", "100"])
        assert args.validation_parallelism == 100

    def test_validate_progress_every_default(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["validate"])
        assert args.progress_every == 100

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

    def test_refresh_accepts_split_json_max_bytes(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["refresh", "--split-json-max-bytes", "100000000"])
        assert args.split_json_max_bytes == 100000000

    def test_export_requires_format(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["export"])

    def test_split_candidates_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            ["split-candidates", "--input", "in.json", "--output-dir", "chunks"]
        )
        assert args.command == "split-candidates"
        assert args.input == "in.json"
        assert args.output_dir == "chunks"
        assert args.shards == 10

    def test_materialize_results_subcommand(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            [
                "materialize-results",
                "--inputs-glob",
                "validated/*.json",
                "--filtered-input",
                "filtered.json",
            ]
        )
        assert args.command == "materialize-results"
        assert args.inputs_glob == "validated/*.json"
        assert args.filtered_input == "filtered.json"

    def test_materialize_results_accepts_split_json_max_bytes(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(
            [
                "materialize-results",
                "--inputs-glob",
                "validated/*.json",
                "--filtered-input",
                "filtered.json",
                "--split-json-max-bytes",
                "100000000",
            ]
        )
        assert args.split_json_max_bytes == 100000000

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


class TestValidateProgressReporter:
    def _progress(self, completed: int, total: int, *, accepted: bool) -> ValidationProgress:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host=f"192.0.2.{completed}",
            port=53,
            path=None,
        )
        result = ValidationResult(
            candidate=candidate,
            accepted=accepted,
            score=100 if accepted else 0,
            status="accepted" if accepted else "rejected",
            reasons=[] if accepted else ["timeout_rate_high"],
            probes=[],
        )
        return ValidationProgress(
            completed=completed, total=total, candidate=candidate, result=result
        )

    def test_progress_interval_and_final_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        reporter = _ValidateProgressReporter(total=234, input_label="in.json", every=100)
        reporter.emit_start()
        for completed in range(1, 235):
            reporter.callback(self._progress(completed, 234, accepted=True))
        reporter.emit_done()

        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert lines[0] == "[validate] start input=in.json total=234"
        assert any("progress done=100 total=234" in line for line in lines)
        assert any("progress done=200 total=234" in line for line in lines)
        assert any("progress done=234 total=234 percent=100" in line for line in lines)
        assert lines[-1].startswith("[validate] done processed=234 total=234 percent=100 ")
        assert "valid=234 invalid=0" in lines[-1]

    def test_parallel_callback_accounting(self, capsys: pytest.CaptureFixture[str]) -> None:
        import concurrent.futures
        import threading

        total = 200
        reporter = _ValidateProgressReporter(total=total, input_label="discovered", every=50)
        reporter.emit_start()

        lock = threading.Lock()
        state = {"completed": 0}

        def worker() -> None:
            while True:
                with lock:
                    state["completed"] += 1
                    completed = state["completed"]
                if completed > total:
                    return
                reporter.callback(self._progress(completed, total, accepted=(completed % 2 == 0)))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for _ in range(8):
                pool.submit(worker)
        reporter.emit_done()

        lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
        assert any("progress done=50 total=200" in line for line in lines)
        assert any("progress done=100 total=200" in line for line in lines)
        assert any("progress done=150 total=200" in line for line in lines)
        assert any("progress done=200 total=200 percent=100" in line for line in lines)
        assert lines[-1].startswith("[validate] done processed=200 total=200 percent=100 ")
        assert "valid=100 invalid=100" in lines[-1]


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


class TestShardCommands:
    def test_split_candidates_writes_even_shards(self, tmp_path: Path) -> None:
        input_path = tmp_path / "candidates.json"
        input_path.write_text(
            json.dumps(
                [
                    {
                        "provider": None,
                        "source": "test",
                        "transport": "dns-udp",
                        "endpoint_url": None,
                        "host": f"192.0.2.{index}",
                        "port": 53,
                        "path": None,
                        "bootstrap_ipv4": [],
                        "bootstrap_ipv6": [],
                        "tls_server_name": None,
                        "metadata": {},
                    }
                    for index in range(1, 6)
                ]
            ),
            encoding="utf-8",
        )

        rc = cmd_split_candidates(
            argparse.Namespace(
                config=None,
                input=str(input_path),
                output_dir=str(tmp_path / "chunks"),
                shards=3,
            )
        )

        assert rc == 0
        manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["shards"] == 3
        assert manifest["total_candidates"] == 5
        chunk_sizes = [
            len(json.loads((tmp_path / "chunks" / f"chunk-{index:02d}.json").read_text()))
            for index in range(3)
        ]
        assert chunk_sizes == [2, 2, 1]

    def test_materialize_results_writes_outputs(self, tmp_path: Path) -> None:
        filtered_path = tmp_path / "filtered.json"
        filtered_path.write_text(
            json.dumps(
                [
                    {
                        "reason": "source_reliability_below_min",
                        "detail": "below minimum",
                        "stage": "source",
                        "candidate": {
                            "provider": None,
                            "source": "publicdns_info",
                            "transport": "dns-udp",
                            "endpoint_url": None,
                            "host": "192.0.2.200",
                            "port": 53,
                            "path": None,
                            "bootstrap_ipv4": [],
                            "bootstrap_ipv6": [],
                            "tls_server_name": None,
                            "metadata": {},
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        shard_dir = tmp_path / "validated"
        shard_dir.mkdir()
        for index, host in enumerate(["192.0.2.1", "192.0.2.2"]):
            (shard_dir / f"shard-{index:02d}.json").write_text(
                json.dumps(
                    [
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
                                "host": host,
                                "port": 53,
                                "path": None,
                                "bootstrap_ipv4": [],
                                "bootstrap_ipv6": [],
                                "tls_server_name": None,
                                "metadata": {},
                            },
                            "probes": [],
                            "median_latency_ms": None,
                        }
                    ]
                ),
                encoding="utf-8",
            )

        config = tmp_path / "config.toml"
        config.write_text(
            "\n".join(
                [
                    "[export]",
                    'formats = ["json", "text", "dnsdist"]',
                    'output_dir = "outputs/latest"',
                ]
            ),
            encoding="utf-8",
        )

        rc = cmd_materialize_results(
            argparse.Namespace(
                config=str(config),
                inputs_glob=str(shard_dir / "*.json"),
                filtered_input=str(filtered_path),
                output=str(tmp_path / "out"),
            )
        )

        assert rc == 0
        assert (tmp_path / "out" / "accepted.json").exists()
        assert (tmp_path / "out" / "candidate.json").exists()
        assert (tmp_path / "out" / "rejected.json").exists()
        assert (tmp_path / "out" / "filtered.json").exists()
        assert (tmp_path / "out" / "resolvers.txt").exists()
        accepted = json.loads((tmp_path / "out" / "accepted.json").read_text(encoding="utf-8"))
        assert [item["candidate"]["host"] for item in accepted] == ["192.0.2.1", "192.0.2.2"]
