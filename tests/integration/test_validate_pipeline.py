"""Integration tests for validation pipeline corpus handling."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from resolver_inventory.cli import cmd_refresh
from resolver_inventory.models import Candidate, DiscoveryResult, FilteredCandidate, ProbeResult
from resolver_inventory.settings import Settings
from resolver_inventory.validate import (
    ValidationProgress,
    validate_candidates,
    validate_candidates_stream,
)
from tests.fixtures.dns_authority import AuthoritativeDnsFixture

pytestmark = pytest.mark.integration


def _candidate(host: str, port: int) -> Candidate:
    return Candidate(
        provider=None,
        source="integration-test",
        transport="dns-udp",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
    )


def _settings_for_mode(mode: str, *, path: str | None = None) -> Settings:
    settings = Settings()
    settings.validation.rounds = 1
    settings.validation.timeout_ms = 1000
    settings.validation.parallelism = 4
    settings.validation.corpus.mode = mode
    settings.validation.corpus.zone = "test.local"
    settings.validation.corpus.path = path
    settings.validation.corpus.schema_version = 1
    return settings


class TestValidateCandidatesCorpusLifecycle:
    def test_controlled_mode_still_works(self) -> None:
        with AuthoritativeDnsFixture() as fix:
            results = validate_candidates(
                [_candidate(fix.host, fix.port)],
                _settings_for_mode("controlled"),
            )

        assert len(results) == 1
        assert results[0].accepted is True

    def test_external_fixture_corpus_works(self) -> None:
        with AuthoritativeDnsFixture() as fix:
            results = validate_candidates(
                [_candidate(fix.host, fix.port)],
                _settings_for_mode("external", path="tests/fixtures/probe-corpus-valid.json"),
            )

        assert len(results) == 1
        assert results[0].accepted is True

    def test_corpus_loaded_once_per_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from resolver_inventory.validate import corpus as corpus_module

        settings = _settings_for_mode("external", path="tests/fixtures/probe-corpus-valid.json")
        candidates = [_candidate("127.0.0.1", 53), _candidate("127.0.0.1", 54)]
        load_calls: list[str] = []

        original_build_corpus = corpus_module.build_corpus

        def spy_build_corpus(config: object) -> object:
            load_calls.append("called")
            return original_build_corpus(config)

        async def fake_run_plain_dns_specs(
            specs: list[object],
            settings: object,
            *,
            timeout_s: float,
            baseline_resolvers: list[str],
            baseline_cache: dict[tuple[str, str], list[str]],
            on_execution=None,
        ) -> list[object]:
            assert on_execution is not None
            for spec in specs:
                await on_execution(
                    type(
                        "Exec",
                        (),
                        {
                            "spec": spec,
                            "result": ProbeResult(
                                ok=True,
                                probe=f"fake:{spec.candidate_idx}",
                                latency_ms=1.0,
                            ),
                        },
                    )()
                )
            return []

        monkeypatch.setattr(
            "resolver_inventory.validate.build_corpus",
            spy_build_corpus,
        )
        monkeypatch.setattr(
            "resolver_inventory.validate._run_plain_dns_specs",
            fake_run_plain_dns_specs,
        )

        results = validate_candidates(candidates, settings)

        assert len(results) == 2
        assert load_calls == ["called"]

    def test_progress_callback_receives_every_completed_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings_for_mode("external", path="tests/fixtures/probe-corpus-valid.json")
        candidates = [_candidate("127.0.0.1", 53), _candidate("127.0.0.1", 54)]
        events: list[ValidationProgress] = []

        async def fake_run_plain_dns_specs(
            specs: list[object],
            settings: object,
            *,
            timeout_s: float,
            baseline_resolvers: list[str],
            baseline_cache: dict[tuple[str, str], list[str]],
            on_execution=None,
        ) -> list[object]:
            assert on_execution is not None
            for spec in specs:
                await on_execution(
                    type(
                        "Exec",
                        (),
                        {
                            "spec": spec,
                            "result": ProbeResult(
                                ok=True,
                                probe=f"fake:{spec.candidate_idx}",
                                latency_ms=1.0,
                            ),
                        },
                    )()
                )
            return []

        monkeypatch.setattr(
            "resolver_inventory.validate._run_plain_dns_specs",
            fake_run_plain_dns_specs,
        )

        results = validate_candidates(candidates, settings, progress_callback=events.append)

        assert len(results) == 2
        assert [event.completed for event in events] == [1, 2]
        assert all(event.total == 2 for event in events)
        assert sorted(str(event.candidate) for event in events) == [
            "dns-udp:127.0.0.1:53",
            "dns-udp:127.0.0.1:54",
        ]

    def test_validate_candidates_stream_emits_in_input_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = _settings_for_mode("external", path="tests/fixtures/probe-corpus-valid.json")
        settings.validation.parallelism = 1
        candidates = [_candidate("127.0.0.1", 54), _candidate("127.0.0.1", 53)]
        seen: list[str] = []

        async def fake_run_plain_dns_specs(
            specs: list[object],
            settings: object,
            *,
            timeout_s: float,
            baseline_resolvers: list[str],
            baseline_cache: dict[tuple[str, str], list[str]],
            on_execution=None,
        ) -> list[object]:
            assert on_execution is not None
            for spec in reversed(specs):
                await on_execution(
                    type(
                        "Exec",
                        (),
                        {
                            "spec": spec,
                            "result": ProbeResult(
                                ok=True,
                                probe=f"fake:{spec.candidate_idx}",
                                latency_ms=1.0,
                            ),
                        },
                    )()
                )
            return []

        monkeypatch.setattr(
            "resolver_inventory.validate._run_plain_dns_specs",
            fake_run_plain_dns_specs,
        )

        validate_candidates_stream(
            candidates,
            lambda result: seen.append(f"{result.candidate.host}:{result.candidate.port}"),
            settings,
        )

        assert seen == ["127.0.0.1:54", "127.0.0.1:53"]

    def test_strict_external_mode_fails_on_invalid_schema(self) -> None:
        settings = _settings_for_mode(
            "external",
            path="tests/fixtures/probe-corpus-invalid-schema.json",
        )
        with pytest.raises(ValueError, match="schema_version"):
            validate_candidates([_candidate("127.0.0.1", 53)], settings)

    def test_external_mode_falls_back_only_when_configured(self) -> None:
        settings = _settings_for_mode(
            "external",
            path="tests/fixtures/probe-corpus-invalid-schema.json",
        )
        settings.validation.corpus.allow_builtin_fallback = True

        results = validate_candidates([_candidate("127.0.0.1", 1)], settings)

        assert len(results) == 1
        assert results[0].accepted is False


class TestRefreshCommandWithProbeCorpus:
    def test_refresh_uses_probe_corpus_override(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        captured: dict[str, str] = {}

        def fake_load_settings(path: str | None) -> Settings:
            settings = _settings_for_mode("controlled")
            settings.export.formats = ["json"]
            settings.export.output_dir = str(tmp_path / "outputs")
            return settings

        def fake_discover_candidates(settings: Settings) -> DiscoveryResult:
            return DiscoveryResult(
                candidates=[_candidate("127.0.0.1", 53)],
                filtered=[
                    FilteredCandidate(
                        candidate=_candidate("127.0.0.2", 53),
                        reason="source_reliability_below_min",
                        detail="public-dns.info reliability 0.20 is below configured minimum 0.50",
                        stage="source",
                    )
                ],
            )

        def fake_normalize(
            raw: list[Candidate],
            *,
            filtered=None,
        ) -> list[Candidate]:
            return raw

        def fake_validate_candidates(
            candidates: list[Candidate],
            settings: Settings,
            progress_callback=None,
        ) -> list[object]:
            captured["mode"] = settings.validation.corpus.mode
            captured["path"] = settings.validation.corpus.path or ""
            assert callable(progress_callback)
            return []

        monkeypatch.setattr("resolver_inventory.settings.load_settings", fake_load_settings)
        monkeypatch.setattr(
            "resolver_inventory.sources.discover_candidates_with_filtered",
            fake_discover_candidates,
        )
        monkeypatch.setattr(
            "resolver_inventory.normalize.dns.normalize_dns_candidates",
            fake_normalize,
        )
        monkeypatch.setattr(
            "resolver_inventory.normalize.doh.normalize_doh_candidates",
            lambda raw, filtered=None: [],
        )
        monkeypatch.setattr(
            "resolver_inventory.validate.validate_candidates",
            fake_validate_candidates,
        )
        monkeypatch.setattr(
            "resolver_inventory.export.json.export_json",
            lambda *args, **kwargs: "[]",
        )
        monkeypatch.setattr(
            "resolver_inventory.export.json.export_filtered_json",
            lambda records, **kwargs: "[]",
        )

        rc = cmd_refresh(
            argparse.Namespace(
                config="configs/default.toml",
                output=str(tmp_path / "outputs"),
                probe_corpus="tests/fixtures/probe-corpus-valid.json",
            )
        )

        assert rc == 0
        assert captured["mode"] == "external"
        assert captured["path"] == "tests/fixtures/probe-corpus-valid.json"
