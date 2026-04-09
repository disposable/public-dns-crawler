"""Unit tests for streamed/windowed validation behavior."""

from __future__ import annotations

import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate import validate_candidates_stream


def _candidate(host: str, port: int) -> Candidate:
    return Candidate(
        provider=None,
        source="unit-test",
        transport="dns-udp",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
    )


def test_validate_candidates_stream_uses_candidate_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings()
    settings.validation.corpus.mode = "controlled"
    settings.validation.corpus.zone = "test.local"
    settings.validation.rounds = 1
    settings.validation.parallelism = 2
    candidates = [
        _candidate("192.0.2.1", 53),
        _candidate("192.0.2.2", 53),
        _candidate("192.0.2.3", 53),
        _candidate("192.0.2.4", 53),
        _candidate("192.0.2.5", 53),
    ]
    window_sizes: list[int] = []

    async def fake_run_window(
        window_candidates,
        settings,
        corpus,
        baseline_cache,
        *,
        start_idx,
        total_candidates,
        total_probes,
        completed_before,
        probes_done_before,
        emit_result,
        progress_callback,
    ):
        window_sizes.append(len(window_candidates))
        for _offset, candidate in enumerate(window_candidates):
            emit_result(
                type(
                    "VR",
                    (),
                    {
                        "candidate": candidate,
                        "status": "accepted",
                        "accepted": True,
                        "score": 100,
                        "reasons": [],
                        "probes": [],
                        "score_breakdown": {},
                        "confidence_score": 0,
                        "score_caps_applied": [],
                        "derived_metrics": {},
                    },
                )()
            )
        return completed_before + len(window_candidates), probes_done_before

    monkeypatch.setattr("resolver_inventory.validate._run_window", fake_run_window)

    seen: list[str] = []
    validate_candidates_stream(
        candidates,
        lambda result: seen.append(result.candidate.host),
        settings,
    )

    assert window_sizes == [2, 2, 1]
    assert seen == ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"]
