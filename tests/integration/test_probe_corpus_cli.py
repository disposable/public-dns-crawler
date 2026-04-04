"""CLI-level integration test for probe corpus generation and validation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.fixtures.dns_authority import AuthoritativeDnsFixture

pytestmark = pytest.mark.integration


def _write_seed_file(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "snapshot_version": 1,
                "generated_at": "2026-04-04T00:00:00Z",
                "sources_used": ["integration-cli-seeds"],
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
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _write_config_file(path: Path, seed_path: Path, resolver: str) -> None:
    path.write_text(
        "\n".join(
            [
                "[probe_corpus]",
                "schema_version = 2",
                'corpus_version = "integration-cli"',
                f'seed_path = "{seed_path.as_posix()}"',
                "",
                "[probe_corpus.baseline]",
                f'resolvers = ["{resolver}", "{resolver}", "{resolver}"]',
                "",
                "[probe_corpus.negative]",
                'parent_zones = ["test.local."]',
                "label_length = 8",
                "validation_rounds = 1",
                "",
                "[probe_corpus.validation.exact]",
                "rounds = 1",
                "required_quorum = 2",
                "",
                "[probe_corpus.validation.consensus]",
                "rounds = 1",
                "required_quorum = 2",
                "",
                "[probe_corpus.validation.negative]",
                "rounds = 1",
                "labels_per_parent = 2",
                "required_quorum = 2",
                "label_length = 8",
                "",
                "[probe_corpus.thresholds]",
                "min_positive_exact = 1",
                "min_positive_consensus = 1",
                "min_negative_generated = 1",
                "",
            ]
        ),
        encoding="utf-8",
    )


def _run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "resolver_inventory.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


class TestProbeCorpusCli:
    def test_generate_then_validate_probe_corpus_outputs(self, tmp_path: Path) -> None:
        seed_file = tmp_path / "probe-corpus-seeds.json"
        config_file = tmp_path / "probe-corpus.toml"
        output_dir = tmp_path / "output"
        _write_seed_file(seed_file)

        with AuthoritativeDnsFixture() as fixture:
            resolver = f"{fixture.host}:{fixture.port}"
            _write_config_file(config_file, seed_file, resolver)

            generate = _run_cli(
                "--log-level",
                "ERROR",
                "generate-probe-corpus",
                "--config",
                str(config_file),
                "--output",
                str(output_dir),
                cwd=Path.cwd(),
            )

            assert generate.returncode == 0, generate.stderr
            assert "candidates_seen=" in generate.stdout
            assert "accepted_probes=" in generate.stdout

            corpus_path = output_dir / "probe-corpus.json"
            validate = _run_cli(
                "--log-level",
                "ERROR",
                "validate-probe-corpus",
                "--config",
                str(config_file),
                "--input",
                str(corpus_path),
                "--schema-version",
                "2",
                cwd=Path.cwd(),
            )

        assert validate.returncode == 0, validate.stderr
        assert corpus_path.exists()
        assert (output_dir / "probe-corpus.yaml").exists()
        assert (output_dir / "metadata.json").exists()
        assert (output_dir / "SUMMARY.md").exists()

        payload = json.loads(corpus_path.read_text(encoding="utf-8"))
        metadata = json.loads((output_dir / "metadata.json").read_text(encoding="utf-8"))

        assert payload["schema_version"] == 2
        assert payload["probe_counts"]["positive_exact"] >= 1
        assert payload["probe_counts"]["positive_consensus"] >= 1
        assert payload["probe_counts"]["negative_generated"] >= 1
        assert metadata["accepted_counts"]["positive_exact"] >= 1
        assert metadata["accepted_counts"]["positive_consensus"] >= 1
        assert metadata["accepted_counts"]["negative_generated"] >= 1
        assert "schema_version=2" in validate.stdout
