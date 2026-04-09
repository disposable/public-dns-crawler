"""Unit tests for settings loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from resolver_inventory.settings import Settings, load_settings


class TestLoadSettings:
    def test_defaults_when_no_file(self) -> None:
        s = load_settings(None)
        assert isinstance(s, Settings)
        assert s.validation.rounds == 3
        assert s.validation.timeout_ms == 2000
        assert s.scoring.accept_min_score == 80

    def test_nonexistent_path_returns_defaults(self, tmp_path: Path) -> None:
        s = load_settings(tmp_path / "does_not_exist.toml")
        assert s.validation.rounds == 3

    def test_load_validation_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(b"[validation]\nrounds = 5\ntimeout_ms = 3000\nparallelism = 20\n")
        s = load_settings(cfg)
        assert s.validation.rounds == 5
        assert s.validation.timeout_ms == 3000
        assert s.validation.parallelism == 20

    def test_load_validation_dns_backend_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(
            b'[validation.dns_backend]\nkind = "massdns"\n'
            b'massdns_bin = "/usr/bin/massdns"\n'
            b'extra_args = ["--bindto", "127.0.0.1", "--rcvbuf=4194304"]\n'
            b"hashmap_size = 4096\nprocesses = 2\nsocket_count = 4\ninterval_ms = 3\n"
            b"predictable = false\nflush = false\nbatch_max_queries = 1111\n"
            b'stderr_log_level = "warning"\nfallback_to_python_on_error = false\n'
        )
        s = load_settings(cfg)
        assert s.validation.dns_backend.kind == "massdns"
        assert s.validation.dns_backend.massdns_bin == "/usr/bin/massdns"
        assert s.validation.dns_backend.extra_args == [
            "--bindto",
            "127.0.0.1",
            "--rcvbuf=4194304",
        ]
        assert s.validation.dns_backend.hashmap_size == 4096
        assert s.validation.dns_backend.processes == 2
        assert s.validation.dns_backend.socket_count == 4
        assert s.validation.dns_backend.interval_ms == 3
        assert s.validation.dns_backend.predictable is False
        assert s.validation.dns_backend.flush is False
        assert s.validation.dns_backend.batch_max_queries == 1111
        assert s.validation.dns_backend.stderr_log_level == "warning"
        assert s.validation.dns_backend.fallback_to_python_on_error is False

    def test_load_scoring_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(b"[scoring]\naccept_min_score = 75\ncandidate_min_score = 50\n")
        s = load_settings(cfg)
        assert s.scoring.accept_min_score == 75
        assert s.scoring.candidate_min_score == 50

    def test_load_corpus_controlled(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(
            b'[validation.corpus]\nmode = "controlled"\nzone = "dns-test.example.net"\n'
        )
        s = load_settings(cfg)
        assert s.validation.corpus.mode == "controlled"
        assert s.validation.corpus.zone == "dns-test.example.net"

    def test_load_corpus_external(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(
            b'[validation.corpus]\nmode = "external"\n'
            b'path = "tests/fixtures/probe-corpus-valid.json"\n'
            b"schema_version = 1\nallow_builtin_fallback = false\nstrict = true\n"
        )
        s = load_settings(cfg)
        assert s.validation.corpus.mode == "external"
        assert s.validation.corpus.path == "tests/fixtures/probe-corpus-valid.json"
        assert s.validation.corpus.schema_version == 1
        assert s.validation.corpus.allow_builtin_fallback is False
        assert s.validation.corpus.strict is True

    def test_load_probe_corpus_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(
            b'[probe_corpus]\nschema_version = 2\ncorpus_version = "dev"\n'
            b'seed_path = "configs/probe-corpus-seeds.json"\n'
            b'[probe_corpus.baseline]\nresolvers = ["127.0.0.1:5300"]\n'
            b'[probe_corpus.negative]\nparent_zones = ["com."]\n'
            b"label_length = 40\nvalidation_rounds = 2\n"
            b"[probe_corpus.selection]\nmax_per_operator_family = 2\nmax_per_tld = 3\n"
            b"[probe_corpus.validation.exact]\nrounds = 2\nrequired_quorum = 2\n"
            b"[probe_corpus.validation.consensus]\nrounds = 2\nrequired_quorum = 2\n"
            b"[probe_corpus.validation.negative]\nrounds = 3\nlabels_per_parent = 3\n"
            b"required_quorum = 2\nlabel_length = 40\n"
            b"[probe_corpus.thresholds]\nmin_positive_exact = 6\n"
            b"min_positive_consensus = 3\nmin_negative_generated = 3\n"
        )
        s = load_settings(cfg)
        assert s.probe_corpus.schema_version == 2
        assert s.probe_corpus.seed_path == "configs/probe-corpus-seeds.json"
        assert s.probe_corpus.baseline.resolvers == ["127.0.0.1:5300"]
        assert s.probe_corpus.negative.parent_zones == ["com."]
        assert s.probe_corpus.validation.exact.required_quorum == 2
        assert s.probe_corpus.thresholds.min_positive_exact == 6

    def test_load_sources(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(
            b'[[sources.dns]]\ntype = "manual"\npath = "seed.txt"\n'
            b'[[sources.doh]]\ntype = "adguard"\n'
        )
        s = load_settings(cfg)
        assert len(s.sources.dns) == 1
        assert s.sources.dns[0].type == "manual"
        assert s.sources.dns[0].path == "seed.txt"
        assert len(s.sources.doh) == 1
        assert s.sources.doh[0].type == "adguard"

    def test_env_var_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_bytes(b"[validation]\nrounds = 7\n")
        monkeypatch.setenv("RESOLVER_INVENTORY_CONFIG", str(cfg))
        s = load_settings(None)
        assert s.validation.rounds == 7
