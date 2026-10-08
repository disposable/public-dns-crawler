"""Unit tests for historical run memory and README reporting."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from resolver_inventory.history import (
    DNS_QUARANTINE_DAYS,
    HISTORY_SCHEMA_VERSION,
    apply_dns_quarantine,
    compute_latest_summary,
    connect_history_db,
    connect_history_db_readonly,
    derive_dns_host_outcomes,
    ensure_history_schema,
    get_resolver_stability_metrics,
    normalize_reasons_signature,
    normalize_resolver_key,
    parse_resolver_key,
    prune_history,
    update_history,
)
from resolver_inventory.models import (
    Candidate,
    FilteredCandidate,
    ProbeResult,
    ValidationResult,
)
from resolver_inventory.readme_report import (
    GENERATED_STATS_END,
    GENERATED_STATS_START,
    render_stats_section,
    replace_generated_section,
)
from resolver_inventory.settings import Settings
from resolver_inventory.validate import _compute_rounds_map, _prepare_plain_dns_work
from resolver_inventory.validate.corpus import Corpus, CorpusEntry


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
            endpoint_url="HTTPS://DNS.Example.COM/DNS-Query?name=Example.COM",
            host="DNS.Example.COM",
            port=443,
            path="/DNS-Query",
        )
        key = normalize_resolver_key(candidate)
        assert key == "doh|https://dns.example.com/DNS-Query?name=Example.COM"

    def test_normalize_doh_key_keeps_distinct_paths(self) -> None:
        a = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="https://dns.example.com/dns-query",
            host="dns.example.com",
            port=443,
            path="/dns-query",
        )
        b = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="https://dns.example.com/DNS-Query",
            host="dns.example.com",
            port=443,
            path="/DNS-Query",
        )
        assert normalize_resolver_key(a) != normalize_resolver_key(b)

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

    def test_normalize_dot_key_hostname(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dot",
            endpoint_url=None,
            host="dns.quad9.net",
            port=853,
            path=None,
            tls_server_name="dns.quad9.net",
        )
        assert normalize_resolver_key(candidate) == "dot|dns.quad9.net|853"

    def test_normalize_dot_key_ip_with_tls_name(self) -> None:
        """An IP endpoint's TLS auth name is part of its identity - two
        endpoints on the same address with different names must not collide
        on the (run_id, resolver_key) primary key."""
        a = Candidate(
            provider=None,
            source="test",
            transport="dot",
            endpoint_url=None,
            host="9.9.9.9",
            port=853,
            path=None,
            tls_server_name="dns.quad9.net",
        )
        b = Candidate(
            provider=None,
            source="test",
            transport="dot",
            endpoint_url=None,
            host="9.9.9.9",
            port=853,
            path=None,
            tls_server_name="other.name.example",
        )
        assert normalize_resolver_key(a) == "dot|9.9.9.9|853|dns.quad9.net"
        assert normalize_resolver_key(b) == "dot|9.9.9.9|853|other.name.example"

    def test_normalize_dot_key_ip_without_tls_name(self) -> None:
        candidate = Candidate(
            provider=None,
            source="test",
            transport="dot",
            endpoint_url=None,
            host="9.9.9.9",
            port=853,
            path=None,
        )
        assert normalize_resolver_key(candidate) == "dot|9.9.9.9|853"

    def test_parse_dot_key_with_tls_name(self) -> None:
        transport, host, port = parse_resolver_key("dot|9.9.9.9|853|dns.quad9.net")
        assert transport == "dot"
        assert host == "9.9.9.9"
        assert port == 853

    def test_parse_dot_key_default_port(self) -> None:
        transport, host, port = parse_resolver_key("dot|dns.quad9.net")
        assert transport == "dot"
        assert host == "dns.quad9.net"
        assert port == 853

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

            # Check runs has one entry
            run_count = connection.execute(
                "SELECT COUNT(*) FROM runs WHERE run_date = ?",
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

    def test_day_status_rejected_when_severe_reason_present(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            day = date(2026, 1, 1)
            first = _metadata(day)
            first.github_run_id = "run-a"
            second = _metadata(day)
            second.github_run_id = "run-b"
            update_history(
                connection,
                first,
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
            update_history(
                connection,
                second,
                [_dns_result("1.1.1.1", "dns-udp", "rejected", ["answer_mismatch"])],
                [],
            )

            status = connection.execute(
                "SELECT day_status FROM resolver_daily WHERE resolver_key = 'dns-udp|1.1.1.1|53'"
            ).fetchone()[0]
            assert status == "rejected"


class TestHistoryCapsAndStreaks:
    """Tests for history-based score caps and streak calculation."""

    def test_no_history_entry_returns_none(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"
        with connect_history_db(db_path) as connection:
            metrics = get_resolver_stability_metrics(connection, resolver_key, date(2026, 1, 5))
            assert metrics is None

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


class TestSchemaManagement:
    def test_creates_only_current_history_tables(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = current_schema()
                    """
                ).fetchall()
            }
            assert "runs" in tables
            assert "run_stats" not in tables
            assert "dns_host_daily" not in tables
            assert {"schema_metadata", "runs", "resolver_run_status", "resolver_daily"}.issubset(
                tables
            )

    def test_rebuilds_incompatible_schema(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            connection.execute("CREATE TABLE run_stats (run_date DATE)")
            connection.execute(
                """
                INSERT OR REPLACE INTO schema_metadata (key, value, updated_at)
                VALUES ('schema_version', '1', CURRENT_TIMESTAMP)
                """
            )
            ensure_history_schema(connection)
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_schema = current_schema()
                    """
                ).fetchall()
            }
            assert "run_stats" not in tables
            version = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            assert int(version) == HISTORY_SCHEMA_VERSION

    def test_prune_history_touches_current_tables(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            old_day = date(2026, 1, 1)
            update_history(
                connection,
                _metadata(old_day),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
            prune_history(connection, run_date=date(2026, 3, 1))
            assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0
            assert connection.execute("SELECT COUNT(*) FROM resolver_run_status").fetchone()[0] == 0
            assert connection.execute("SELECT COUNT(*) FROM resolver_daily").fetchone()[0] == 0


def _filtered(host: str = "198.51.100.1") -> FilteredCandidate:
    return FilteredCandidate(
        candidate=Candidate(
            provider=None,
            source="test",
            transport="dns-udp",
            endpoint_url=None,
            host=host,
            port=53,
            path=None,
        ),
        reason="invalid_dns_host",
        detail="test filtered candidate",
        stage="source",
    )


class TestSummaryCountsAndDeltas:
    """compute_latest_summary reports filtered counts and per-run deltas."""

    def test_first_run_records_filtered_and_deltas(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [
                    _dns_result("1.1.1.1", "dns-udp", "accepted"),
                    _dns_result("2.2.2.2", "dns-udp", "rejected"),
                ],
                [_filtered(), _filtered("198.51.100.2")],
            )
            summary = compute_latest_summary(connection)
        assert summary["accepted_count"] == 1
        assert summary["rejected_count"] == 1
        assert summary["filtered_count"] == 2
        # With no previous run, deltas are relative to zero
        assert summary["accepted_delta"] == 1
        assert summary["rejected_delta"] == 1

    def test_deltas_compare_to_previous_run(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [
                    _dns_result("1.1.1.1", "dns-udp", "accepted"),
                    _dns_result("2.2.2.2", "dns-udp", "rejected"),
                ],
                [_filtered(), _filtered("198.51.100.2")],
            )
            update_history(
                connection,
                _metadata(date(2026, 1, 2)),
                [
                    _dns_result("1.1.1.1", "dns-udp", "accepted"),
                    _dns_result("3.3.3.3", "dns-udp", "accepted"),
                ],
                [_filtered()],
            )
            summary = compute_latest_summary(connection)
        assert summary["accepted_count"] == 2
        assert summary["rejected_count"] == 0
        assert summary["filtered_count"] == 1
        assert summary["accepted_delta"] == 1
        assert summary["rejected_delta"] == -1


class TestSchemaMigration:
    """Older schema versions migrate in place instead of rebuilding."""

    def test_v3_schema_migrates_preserving_data(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [_filtered()],
            )
            # Simulate a v3 database: drop the v4 column and mark version 3
            connection.execute("ALTER TABLE runs DROP COLUMN filtered_count")
            connection.execute(
                "UPDATE schema_metadata SET value = '3' WHERE key = 'schema_version'"
            )

        # Reopening must migrate v3 -> v4 in place, keeping existing rows
        with connect_history_db(db_path) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()}
            assert "filtered_count" in columns
            assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
            version = connection.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()[0]
            assert int(version) == HISTORY_SCHEMA_VERSION
            # Old v3 row predates filtered tracking: count defaults to zero
            filtered_count = connection.execute("SELECT filtered_count FROM runs").fetchone()[0]
            assert filtered_count == 0

    def test_unknown_schema_version_rebuilds(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
            connection.execute(
                "UPDATE schema_metadata SET value = '99' WHERE key = 'schema_version'"
            )

        with connect_history_db(db_path) as connection:
            assert connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 0


class TestReadonlyHistoryConnection:
    """Validation opens history read-only and degrades gracefully."""

    def test_missing_database_returns_none(self, tmp_path) -> None:
        assert connect_history_db_readonly(tmp_path / "nope.duckdb") is None

    def test_empty_database_returns_none(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        db_path.touch()
        assert connect_history_db_readonly(db_path) is None

    def test_opens_existing_database(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
        connection = connect_history_db_readonly(db_path)
        try:
            assert connection is not None
            metrics = get_resolver_stability_metrics(
                connection,
                "dns-udp|1.1.1.1|53",
                date(2026, 1, 2),
            )
            assert metrics is not None
            assert metrics.runs_seen_30d == 1
        finally:
            connection.close()


class TestStreakAnchor:
    """Streaks anchor at the latest observed day, not the requested run_date."""

    def test_streak_anchored_at_latest_observed_day(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        resolver_key = "dns-udp|1.1.1.1|53"
        with connect_history_db(db_path) as connection:
            for offset in range(3):
                day = date(2026, 1, 1) + timedelta(days=offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                    [],
                )
            # Query a date whose rollup has not been written yet (validation
            # runs before today's update_history call)
            metrics = get_resolver_stability_metrics(
                connection,
                resolver_key,
                date(2026, 1, 5),
            )
            assert metrics is not None
            assert metrics.consecutive_success_days == 3
            assert metrics.consecutive_fail_days == 0


def _udp_candidate(host: str) -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport="dns-udp",
        endpoint_url=None,
        host=host,
        port=53,
        path=None,
    )


class TestRevalidationRounds:
    """Stable resolvers get reduced probe rounds when history is consulted."""

    def test_disabled_returns_none(self) -> None:
        settings = Settings()  # revalidation_stable_days defaults to 0
        assert (
            _compute_rounds_map([_udp_candidate("1.1.1.1")], settings, object(), date(2026, 1, 1))
            is None
        )

    def test_no_history_connection_returns_none(self) -> None:
        settings = Settings()
        settings.validation.revalidation_stable_days = 7
        assert (
            _compute_rounds_map([_udp_candidate("1.1.1.1")], settings, None, date(2026, 1, 1))
            is None
        )

    def test_stable_resolver_gets_reduced_rounds(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            for offset in range(8):
                day = date(2026, 1, 1) + timedelta(days=offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                    [],
                )
            settings = Settings()
            settings.validation.revalidation_stable_days = 7
            settings.validation.revalidation_stable_rounds = 1
            rounds_map = _compute_rounds_map(
                [_udp_candidate("1.1.1.1"), _udp_candidate("9.9.9.9")],
                settings,
                connection,
                date(2026, 1, 9),
            )
        assert rounds_map == {0: 1}

    def test_recent_failure_keeps_full_rounds(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            for offset in range(8):
                day = date(2026, 1, 1) + timedelta(days=offset)
                update_history(
                    connection,
                    _metadata(day),
                    [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                    [],
                )
            update_history(
                connection,
                _metadata(date(2026, 1, 9)),
                [_dns_result("1.1.1.1", "dns-udp", "rejected", ["timeout"])],
                [],
            )
            settings = Settings()
            settings.validation.revalidation_stable_days = 7
            settings.validation.revalidation_stable_rounds = 1
            rounds_map = _compute_rounds_map(
                [_udp_candidate("1.1.1.1")],
                settings,
                connection,
                date(2026, 1, 10),
            )
        assert rounds_map is None

    def test_prepare_uses_per_candidate_rounds(self) -> None:
        corpus = Corpus(
            positive=[
                CorpusEntry(
                    qname="a.ok.test.",
                    rdtype="A",
                    expected_mode="exact_rrset",
                    expected_answers=["192.0.2.1"],
                    label="a",
                )
            ],
            nxdomain=[CorpusEntry(qname="nx.test.", rdtype="A", label="nx")],
        )
        candidates = [_udp_candidate("1.1.1.1"), _udp_candidate("9.9.9.9")]
        prepared = _prepare_plain_dns_work(candidates, corpus, 3, {0: 1})
        try:
            # stable candidate: 1 round x (1 positive + 1 nxdomain)
            # unstable candidate: 3 rounds x 2
            assert prepared.probes_expected == {0: 2, 1: 6}
            assert prepared.total_probes == 8
        finally:
            for child in prepared.temp_dir.iterdir():
                child.unlink()
            prepared.temp_dir.rmdir()


def _dot_result(host: str, status: str, port: int = 853) -> ValidationResult:
    return ValidationResult(
        candidate=Candidate(
            provider=None,
            source="test",
            transport="dot",
            endpoint_url=None,
            host=host,
            port=port,
            path=None,
            tls_server_name=host,
        ),
        accepted=status == "accepted",
        score=90 if status == "accepted" else 10,
        status=status,  # type: ignore[arg-type]
        reasons=[],
        probes=[ProbeResult(ok=status == "accepted", probe="probe", error=None)],
    )


class TestChangelog:
    def test_none_with_fewer_than_two_runs(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result("1.1.1.1", "dns-udp", "accepted")],
                [],
            )
            from resolver_inventory.history import compute_changelog

            assert compute_changelog(connection) is None

    def test_diffs_two_runs(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [
                    _dns_result("1.1.1.1", "dns-udp", "accepted"),
                    _dns_result("8.8.8.8", "dns-udp", "accepted"),
                    _dot_result("dns.quad9.net", "accepted"),
                ],
                [],
            )
            update_history(
                connection,
                _metadata(date(2026, 1, 2)),
                [
                    _dns_result("1.1.1.1", "dns-udp", "accepted"),
                    _dns_result("8.8.8.8", "dns-udp", "rejected", ["timeout"]),
                    _dns_result("9.9.9.9", "dns-udp", "accepted"),
                ],
                [],
            )
            from resolver_inventory.history import compute_changelog

            changelog = compute_changelog(connection)

        assert changelog is not None
        assert changelog["run_date"] == "2026-01-02"
        assert changelog["previous_run_date"] == "2026-01-01"
        assert changelog["added_count"] == 1
        assert changelog["added"] == ["dns-udp|9.9.9.9|53"]
        assert changelog["removed_count"] == 1
        assert changelog["removed"] == ["dot|dns.quad9.net|853"]
        assert changelog["transition_counts"] == {"accepted->rejected": 1}
        assert changelog["status_changes_total"] == 1
        assert changelog["status_changes"] == [
            {"resolver": "dns-udp|8.8.8.8|53", "from": "accepted", "to": "rejected"}
        ]

    def test_no_changes_between_runs(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            results = [_dns_result("1.1.1.1", "dns-udp", "accepted")]
            update_history(connection, _metadata(date(2026, 1, 1)), results, [])
            update_history(connection, _metadata(date(2026, 1, 2)), results, [])
            from resolver_inventory.history import compute_changelog

            changelog = compute_changelog(connection)

        assert changelog is not None
        assert changelog["added_count"] == 0
        assert changelog["removed_count"] == 0
        assert changelog["status_changes_total"] == 0
        assert changelog["transition_counts"] == {}

    def test_truncation_caps_added_list(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(connection, _metadata(date(2026, 1, 1)), [], [])
            update_history(
                connection,
                _metadata(date(2026, 1, 2)),
                [_dns_result(f"10.0.0.{i}", "dns-udp", "accepted") for i in range(1, 8)],
                [],
            )
            from resolver_inventory.history import compute_changelog

            changelog = compute_changelog(connection, max_entries=3)

        assert changelog is not None
        assert changelog["added_count"] == 7
        assert len(changelog["added"]) == 3
        assert changelog["truncated"] is True

    def test_truncation_covers_status_changes(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        with connect_history_db(db_path) as connection:
            update_history(
                connection,
                _metadata(date(2026, 1, 1)),
                [_dns_result(f"10.0.0.{i}", "dns-udp", "accepted") for i in range(1, 8)],
                [],
            )
            update_history(
                connection,
                _metadata(date(2026, 1, 2)),
                [_dns_result(f"10.0.0.{i}", "dns-udp", "rejected") for i in range(1, 8)],
                [],
            )
            from resolver_inventory.history import compute_changelog

            changelog = compute_changelog(connection, max_entries=3)

        assert changelog is not None
        assert changelog["status_changes_total"] == 7
        assert len(changelog["status_changes"]) == 3
        assert changelog["truncated"] is True

    def test_readme_section_renders_changelog(self) -> None:
        section = render_stats_section(
            {
                "latest_run_date": "2026-01-02",
                "latest_run_id": "run-2",
                "runs_tracked": 2,
                "accepted_count": 10,
                "candidate_count": 2,
                "rejected_count": 5,
                "filtered_count": 1,
                "accepted_delta": 4,
                "rejected_delta": -1,
                "quarantined_count": 0,
                "top_reasons": [],
            },
            {
                "run_id": "run-2",
                "run_date": "2026-01-02",
                "previous_run_id": "run-1",
                "previous_run_date": "2026-01-01",
                "added_count": 3,
                "added": ["dns-udp|9.9.9.9|53"],
                "removed_count": 1,
                "removed": ["dot|dns.quad9.net|853"],
                "transition_counts": {"accepted->rejected": 2},
                "status_changes": [],
                "status_changes_total": 2,
                "truncated": False,
            },
        )
        assert "Latest Run Changes" in section
        assert "+3" in section and "-1" in section
        assert "accepted->rejected" in section
