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
