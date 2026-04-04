"""Unit tests for historical run memory and README reporting."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from resolver_inventory.history import (
    DNS_QUARANTINE_DAYS,
    apply_dns_quarantine,
    connect_history_db,
    derive_dns_host_outcomes,
    normalize_reasons_signature,
    update_history,
)
from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.readme_report import (
    GENERATED_STATS_END,
    GENERATED_STATS_START,
    render_stats_section,
    replace_generated_section,
)


def _dns_result(
    host: str,
    transport: str,
    status: str,
    reasons: list[str] | None = None,
) -> ValidationResult:
    return ValidationResult(
        candidate=Candidate(
            provider=None,
            source="test",
            transport=transport,  # type: ignore[arg-type]
            endpoint_url=None,
            host=host,
            port=53,
            path=None,
        ),
        accepted=status == "accepted",
        score=90 if status == "accepted" else 10,
        status=status,  # type: ignore[arg-type]
        reasons=reasons or [],
        probes=[ProbeResult(ok=status == "accepted", probe="probe", error=None)],
    )


def _metadata(day: date):
    generated_at = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    from resolver_inventory.history import RunMetadata

    return RunMetadata(
        run_date=day,
        generated_at=generated_at,
        github_run_id=f"run-{day.isoformat()}",
        repo_sha="repo-sha",
        crawler_sha="crawler-sha",
    )


class TestHostOutcomes:
    def test_derive_rejected_host_outcome(self) -> None:
        outcomes = derive_dns_host_outcomes(
            [
                _dns_result("192.0.2.1", "dns-udp", "rejected", ["timeout_rate_high"]),
                _dns_result("192.0.2.1", "dns-tcp", "rejected", ["answer_mismatch"]),
            ]
        )
        assert outcomes[0].status == "rejected"
        assert outcomes[0].reasons_signature == normalize_reasons_signature(
            ["answer_mismatch", "timeout_rate_high"]
        )

    def test_candidate_breaks_rejected_status(self) -> None:
        outcomes = derive_dns_host_outcomes(
            [
                _dns_result("192.0.2.1", "dns-udp", "candidate"),
                _dns_result("192.0.2.1", "dns-tcp", "rejected", ["timeout_rate_high"]),
            ]
        )
        assert outcomes[0].status == "candidate"


class TestQuarantineLifecycle:
    def test_fourteen_day_rejected_streak_triggers_quarantine(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        host = "192.0.2.10"
        with connect_history_db(db_path) as connection:
            for day_offset in range(14):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [
                        _dns_result(host, "dns-udp", "rejected", ["timeout_rate_high"]),
                        _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                    ],
                    [],
                )

            candidates, filtered = apply_dns_quarantine(
                connection,
                date(2026, 1, 14),
                [
                    Candidate(
                        provider=None,
                        source="test",
                        transport="dns-udp",
                        endpoint_url=None,
                        host=host,
                        port=53,
                        path=None,
                    ),
                    Candidate(
                        provider=None,
                        source="test",
                        transport="dns-tcp",
                        endpoint_url=None,
                        host=host,
                        port=53,
                        path=None,
                    ),
                ],
                [],
            )

        assert candidates == []
        assert len(filtered) == 2
        assert all(record.reason == "historical_dns_quarantine" for record in filtered)

    def test_candidate_does_not_start_quarantine_streak(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        host = "192.0.2.11"
        with connect_history_db(db_path) as connection:
            for day_offset in range(13):
                day = date(2026, 2, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [
                        _dns_result(host, "dns-udp", "rejected", ["timeout_rate_high"]),
                        _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                    ],
                    [],
                )
            update_history(
                connection,
                _metadata(date(2026, 2, 14)),
                [
                    _dns_result(host, "dns-udp", "candidate"),
                    _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                ],
                [],
            )

            candidates, _filtered = apply_dns_quarantine(
                connection,
                date(2026, 2, 14),
                [
                    Candidate(
                        provider=None,
                        source="test",
                        transport="dns-udp",
                        endpoint_url=None,
                        host=host,
                        port=53,
                        path=None,
                    )
                ],
                [],
            )

        assert len(candidates) == 1

    def test_same_rejection_after_retry_restarts_quarantine(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        host = "192.0.2.12"
        start = date(2026, 3, 1)
        with connect_history_db(db_path) as connection:
            for day_offset in range(14):
                day = start + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [
                        _dns_result(host, "dns-udp", "rejected", ["timeout_rate_high"]),
                        _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                    ],
                    [],
                )

            retry_day = start + timedelta(days=13 + DNS_QUARANTINE_DAYS)
            update_history(
                connection,
                _metadata(retry_day),
                [
                    _dns_result(host, "dns-udp", "rejected", ["timeout_rate_high"]),
                    _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                ],
                [],
            )
            row = connection.execute(
                "SELECT retry_after, cycles FROM dns_host_quarantine WHERE host = ?",
                [host],
            ).fetchone()

        assert row[0] == retry_day + timedelta(days=DNS_QUARANTINE_DAYS)
        assert row[1] == 2

    def test_prunes_run_history_but_keeps_quarantine(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        host = "192.0.2.13"
        with connect_history_db(db_path) as connection:
            for day_offset in range(14):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [
                        _dns_result(host, "dns-udp", "rejected", ["timeout_rate_high"]),
                        _dns_result(host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                    ],
                    [],
                )
            for day_offset in range(14, 45):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result(f"192.0.2.{day_offset}", "dns-udp", "accepted")],
                    [],
                )
            runs_count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            quarantine_count = connection.execute(
                "SELECT COUNT(*) FROM dns_host_quarantine WHERE host = ?",
                [host],
            ).fetchone()[0]

        assert runs_count == 30
        assert quarantine_count == 1


class TestReadmeReport:
    def test_replace_only_generated_section(self) -> None:
        original = "\n".join(
            [
                "# Title",
                GENERATED_STATS_START,
                "old",
                GENERATED_STATS_END,
                "after",
            ]
        )
        updated = replace_generated_section(
            original,
            render_stats_section(
                {
                    "latest_run_date": "2026-04-05",
                    "latest_run_id": "123",
                    "runs_tracked": 2,
                    "accepted_count": 10,
                    "candidate_count": 1,
                    "rejected_count": 2,
                    "filtered_count": 3,
                    "accepted_delta": 4,
                    "rejected_delta": -1,
                    "quarantined_count": 5,
                    "top_reasons": [("timeout_rate_high", 7)],
                }
            ),
        )
        assert "# Title" in updated
        assert "after" in updated
        assert "timeout_rate_high" in updated

    def test_render_empty_summary(self) -> None:
        section = render_stats_section(
            {
                "latest_run_date": None,
                "latest_run_id": None,
                "runs_tracked": 0,
                "accepted_count": 0,
                "candidate_count": 0,
                "rejected_count": 0,
                "filtered_count": 0,
                "accepted_delta": 0,
                "rejected_delta": 0,
                "quarantined_count": 0,
                "top_reasons": [],
            }
        )
        assert GENERATED_STATS_START in section
        assert GENERATED_STATS_END in section
        assert "No rejected DNS history" in section
