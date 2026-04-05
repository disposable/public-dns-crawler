"""Unit tests for historical run memory and README reporting."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from resolver_inventory.history import (
    DNS_QUARANTINE_DAYS,
    apply_dns_quarantine,
    connect_history_db,
    derive_dns_host_outcomes,
    get_resolver_stability_metrics,
    migrate_legacy_to_v2,
    normalize_reasons_signature,
    normalize_resolver_key,
    parse_resolver_key,
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


class TestResolverKeyNormalization:
    """Tests for resolver_key normalization and parsing."""

    def test_normalize_dns_udp_key(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host="1.1.1.1",
            port=53,
            path=None,
        )
        key = normalize_resolver_key(candidate)
        assert key == "dns-udp|1.1.1.1|53"

    def test_normalize_dns_tcp_key(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-tcp",
            endpoint_url=None,
            host="8.8.8.8",
            port=53,
            path=None,
        )
        key = normalize_resolver_key(candidate)
        assert key == "dns-tcp|8.8.8.8|53"

    def test_normalize_doh_key(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="https://dns.example.com/dns-query",
            host="dns.example.com",
            port=443,
            path="/dns-query",
        )
        key = normalize_resolver_key(candidate)
        assert key == "doh|https://dns.example.com/dns-query"

    def test_normalize_doh_key_trailing_slash(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="https://dns.example.com/dns-query/",
            host="dns.example.com",
            port=443,
            path="/dns-query/",
        )
        key = normalize_resolver_key(candidate)
        assert key == "doh|https://dns.example.com/dns-query"

    def test_normalize_doh_key_uppercase(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="https://DNS.Example.COM/dns-query",
            host="DNS.Example.COM",
            port=443,
            path="/dns-query",
        )
        key = normalize_resolver_key(candidate)
        assert key == "doh|https://dns.example.com/dns-query"

    def test_parse_dns_key(self) -> None:
        transport, host, port = parse_resolver_key("dns-udp|1.1.1.1|53")
        assert transport == "dns-udp"
        assert host == "1.1.1.1"
        assert port == 53

    def test_parse_doh_key(self) -> None:
        transport, url, port = parse_resolver_key("doh|https://dns.example.com/query")
        assert transport == "doh"
        assert url == "https://dns.example.com/query"
        assert port is None

    def test_same_host_different_transports_different_keys(self) -> None:
        """Same host on UDP and TCP should have different resolver_keys."""
        udp_candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host="1.1.1.1",
            port=53,
            path=None,
        )
        tcp_candidate = Candidate(
            provider=None,
            source="test",
            transport="dns-tcp",
            endpoint_url=None,
            host="1.1.1.1",
            port=53,
            path=None,
        )
        udp_key = normalize_resolver_key(udp_candidate)
        tcp_key = normalize_resolver_key(tcp_candidate)
        assert udp_key != tcp_key
        assert "dns-udp" in udp_key
        assert "dns-tcp" in tcp_key


class TestDoHHistoryTracking:
    """Tests for DoH resolver history tracking."""

    def _doh_result(
        self,
        url: str,
        status: str,
        reasons: list[str] | None = None,
    ) -> ValidationResult:
        host = url.replace("https://", "").split("/")[0]
        return ValidationResult(
            candidate=Candidate(
                provider=None,
                source="test",
                transport="doh",
                endpoint_url=url,
                host=host,
                port=443,
                path="/dns-query",
            ),
            accepted=status == "accepted",
            score=90 if status == "accepted" else 10,
            status=status,  # type: ignore[arg-type]
            reasons=reasons or [],
            probes=[ProbeResult(ok=status == "accepted", probe="probe", error=None)],
        )

    def test_doh_resolver_has_history_in_resolver_daily(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        url = "https://dns.example.com/dns-query"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(day),
                [self._doh_result(url, "accepted")],
                [],
            )

            # Check resolver_daily has DoH entry
            row = connection.execute(
                "SELECT resolver_key, day_status FROM resolver_daily WHERE transport = 'doh'"
            ).fetchone()
            assert row is not None
            assert row[0] == f"doh|{url}"
            assert row[1] == "accepted"

    def test_doh_history_metrics_available(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        url = "https://dns.example.com/dns-query"
        resolver_key = f"doh|{url}"

        with connect_history_db(db_path) as connection:
            # Add 7 days of DoH history
            for day_offset in range(7):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [self._doh_result(url, "accepted")],
                    [],
                )

            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 7))
            assert metrics is not None
            assert metrics.runs_seen_7d == 7
            assert metrics.success_days_7d == 7
            assert metrics.resolver_key == resolver_key
            assert metrics.transport == "doh"

    def test_doh_and_dns_same_host_separate_history(self, tmp_path) -> None:
        """DoH and DNS on same host should have separate history entries."""
        db_path = tmp_path / "history.duckdb"
        host = "dns.example.com"
        doh_url = f"https://{host}/dns-query"

        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(day),
                [
                    self._doh_result(doh_url, "accepted"),
                    _dns_result(host, "dns-udp", "rejected", ["timeout"]),
                ],
                [],
            )

            # Check both entries exist in resolver_daily
            rows = connection.execute(
                "SELECT transport, day_status FROM resolver_daily WHERE host = ?",
                [host],
            ).fetchall()
            assert len(rows) == 2
            transports = {r[0] for r in rows}
            assert "doh" in transports
            assert "dns-udp" in transports


class TestDailyRollupAggregation:
    """Tests for daily rollup aggregation from run-level data."""

    def test_single_run_daily_rollup(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(day),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )

            row = connection.execute(
                """SELECT runs_that_day, successful_runs_that_day, failed_runs_that_day
                   FROM resolver_daily WHERE resolver_key = 'dns-udp|1.1.1.1|53'"""
            ).fetchone()
            assert row == (1, 1, 0)

    def test_multiple_runs_same_day_aggregation(self, tmp_path) -> None:
        """Multiple runs on same day should aggregate into single daily row."""
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)

            # First run - accepted
            metadata1 = _metadata(day)
            # Modify github_run_id to make runs distinct
            metadata1 = metadata1.__class__(
                run_date=metadata1.run_date,
                generated_at=metadata1.generated_at,
                github_run_id="run-1",
                repo_sha=metadata1.repo_sha,
                crawler_sha=metadata1.crawler_sha,
            )
            update_history(
                connection,
                metadata1,
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )

            # Check runs_v2 has one entry
            run_count = connection.execute(
                "SELECT COUNT(*) FROM runs_v2 WHERE run_date = ?",
                [day],
            ).fetchone()[0]
            assert run_count == 1

    def test_day_status_accepted_when_all_accepted(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(day),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )

            status = connection.execute("SELECT day_status FROM resolver_daily").fetchone()[0]
            assert status == "accepted"

    def test_day_status_rejected_when_all_rejected(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(day),
                [_dns_result("1.1.1.1", "dns-udp", "rejected", ["timeout"])],
                [],
            )

            status = connection.execute("SELECT day_status FROM resolver_daily").fetchone()[0]
            assert status == "rejected"


class TestHistoryCapsAndStreaks:
    """Tests for history-based score caps and streak calculation."""

    def test_consecutive_success_days_counting(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"

        with connect_history_db(db_path) as connection:
            # 5 consecutive accepted days
            for day_offset in range(5):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                    [],
                )

            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 5))
            assert metrics is not None
            assert metrics.consecutive_success_days == 5
            assert metrics.consecutive_fail_days == 0

    def test_consecutive_fail_days_counting(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"

        with connect_history_db(db_path) as connection:
            # 3 consecutive rejected days
            for day_offset in range(3):
                day = date(2026, 1, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", "rejected", ["timeout"])],
                    [],
                )

            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 3))
            assert metrics is not None
            assert metrics.consecutive_success_days == 0
            assert metrics.consecutive_fail_days == 3

    def test_gap_breaks_streak(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"

        with connect_history_db(db_path) as connection:
            # Day 1: accepted
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
            # Day 3: accepted (gap on day 2)
            update_history(
                connection,
                _metadata(date(2026, 1, 3)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )

            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 3))
            assert metrics is not None
            # Streak should be 1 (just day 3), not 2
            assert metrics.consecutive_success_days == 1

    def test_status_flaps_counting(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"

        with connect_history_db(db_path) as connection:
            # Create pattern: accepted -> rejected -> accepted (2 flaps)
            days_status = [
                (date(2026, 1, 1), "accepted"),
                (date(2026, 1, 2), "rejected"),
                (date(2026, 1, 3), "accepted"),
            ]
            for day, status in days_status:
                reasons = ["timeout"] if status == "rejected" else []
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", status, reasons)],
                    [],
                )

            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 3))
            assert metrics is not None
            assert metrics.status_flaps_30d == 2


class TestMigration:
    """Tests for schema migration from legacy to v2."""

    def test_migrate_legacy_dns_data(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"

        with connect_history_db(db_path) as connection:
            # Insert legacy data
            connection.execute(
                """INSERT INTO runs VALUES
                (?, ?, ?, ?, ?)""",
                [date(2026, 1, 1), datetime(2026, 1, 1, 0, 0, 0), "run-1", "sha-1", "crawler-1"],
            )
            connection.execute(
                """INSERT INTO dns_host_daily VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    date(2026, 1, 1),
                    "1.1.1.1",
                    "accepted",
                    "",
                    "[]",
                    1,
                    0,
                    0,
                    "accepted",
                    "accepted",
                ],
            )

            # Run migration
            stats = migrate_legacy_to_v2(connection, dry_run=False)

            assert stats["runs_migrated"] == 1
            assert stats["dns_hosts_migrated"] == 1
            assert stats["resolver_daily_created"] == 2  # UDP + TCP

            # Verify v2 tables populated
            v2_count = connection.execute("SELECT COUNT(*) FROM resolver_daily").fetchone()[0]
            assert v2_count == 2

    def test_dry_run_does_not_write(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"

        with connect_history_db(db_path) as connection:
            # Insert legacy data
            connection.execute(
                """INSERT INTO runs VALUES
                (?, ?, ?, ?, ?)""",
                [date(2026, 1, 1), datetime(2026, 1, 1, 0, 0, 0), "run-1", "sha-1", "crawler-1"],
            )
            connection.execute(
                """INSERT INTO dns_host_daily VALUES
                (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    date(2026, 1, 1),
                    "1.1.1.1",
                    "accepted",
                    "",
                    "[]",
                    1,
                    0,
                    0,
                    "accepted",
                    "accepted",
                ],
            )

            # Run dry-run migration
            stats = migrate_legacy_to_v2(connection, dry_run=True)

            assert stats["runs_migrated"] == 1
            assert stats["resolver_daily_created"] == 2

            # Verify v2 tables NOT populated
            v2_count = connection.execute("SELECT COUNT(*) FROM resolver_daily").fetchone()[0]
            assert v2_count == 0
