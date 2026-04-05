"""Historical run memory and DNS quarantine helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb

from resolver_inventory.models import (
    Candidate,
    DnsHostOutcome,
    FilteredCandidate,
    Status,
    ValidationResult,
)
from resolver_inventory.util.url import canonicalize_doh_url

HISTORY_RETENTION_DAYS = 30
DNS_QUARANTINE_STREAK_DAYS = 14
DNS_QUARANTINE_DAYS = 90

# Schema version for current history schema.
HISTORY_SCHEMA_VERSION = 3

CURRENT_HISTORY_TABLES = {
    "schema_metadata",
    "runs",
    "resolver_run_status",
    "resolver_daily",
    "dns_host_quarantine",
}

LEGACY_HISTORY_TABLES = {
    "run_stats",
    "dns_host_daily",
}

SEVERE_CORRECTNESS_REASONS: frozenset[str] = frozenset(
    {
        "nxdomain_spoofing",
        "tls_name_mismatch",
        "tls_error",
        "answer_mismatch",
        "doh_path_invalid",
    }
)


def normalize_resolver_key(candidate: Candidate) -> str:
    """Generate a canonical endpoint-level identity key for a resolver.

    Format:
    - dns-udp|host|port
    - dns-tcp|host|port
    - doh|url (canonicalized)

    This allows distinguishing:
    - Same host, different transports (UDP vs TCP)
    - Same host:port, different paths (DoH variants)
    - Different ports on same host
    """
    if candidate.transport == "doh":
        url = canonicalize_doh_url(candidate.endpoint_url or "")
        if not url:
            url = candidate.endpoint_url or ""
        return f"doh|{url}"
    else:
        # For plain DNS, use transport|host|port
        return f"{candidate.transport}|{candidate.host}|{candidate.port}"


def parse_resolver_key(resolver_key: str) -> tuple[str, str, int | None]:
    """Parse a resolver_key back into components.

    Returns: (transport, host_or_url, port_or_none)
    """
    transport, sep, remainder = resolver_key.partition("|")
    if not sep:
        return ("unknown", resolver_key, None)

    if transport == "doh":
        return (transport, remainder, None)

    host, _, port_text = remainder.partition("|")
    try:
        port = int(port_text) if port_text else 53
    except ValueError:
        port = 53
    return (transport, host, port)


@dataclass(slots=True)
class RunMetadata:
    run_date: date
    generated_at: datetime
    github_run_id: str
    repo_sha: str
    crawler_sha: str
    run_type: str = "scheduled"  # scheduled, manual, local


@dataclass(slots=True)
class RunInfo:
    """Extended run metadata for runs table."""

    run_id: str  # Unique run identifier (e.g., github_run_id + timestamp)
    run_date: date
    run_started_at: datetime
    generated_at: datetime
    github_run_id: str
    repo_sha: str
    crawler_sha: str
    run_type: str


@dataclass(slots=True)
class ResolverRunStatus:
    """Per-resolver status for a single run."""

    run_id: str
    resolver_key: str
    host: str
    transport: str
    # Endpoint metadata for debugging
    endpoint_url: str | None
    port: int | None
    path: str | None
    # Status
    status: str
    reasons_signature: str
    reasons_json: str
    # Probe counts
    accepted_probe_count: int
    failed_probe_count: int
    total_probe_count: int
    # Latency metrics (if available)
    p50_latency_ms: float | None
    p95_latency_ms: float | None
    jitter_ms: float | None


@dataclass(slots=True)
class ResolverDaily:
    """Daily rollup of resolver status across all runs in a day."""

    run_date: date
    resolver_key: str
    host: str
    transport: str
    # Aggregated status
    day_status: str
    reasons_signature: str
    reasons_json: str
    # Run counts
    runs_that_day: int
    successful_runs_that_day: int
    failed_runs_that_day: int
    flapped_within_day: bool
    # Latency aggregates (if available)
    p50_latency_ms: float | None
    p95_latency_ms: float | None
    jitter_ms: float | None


@dataclass(slots=True)
class QuarantineRecord:
    host: str
    first_quarantined_on: date
    last_quarantined_on: date
    retry_after: date
    reasons_signature: str
    reasons_json: str
    cycles: int


@dataclass(slots=True)
class ResolverStabilityMetrics:
    """Per-resolver stability metrics computed from historical data."""

    host: str
    transport: str
    runs_seen_7d: int
    runs_seen_30d: int
    success_days_7d: int
    success_days_30d: int
    consecutive_success_days: int
    consecutive_fail_days: int
    status_flaps_30d: int
    latest_status: str | None = None
    flapped_within_day_7d: int = 0  # Days with intra-day flapping
    flapped_within_day_30d: int = 0
    resolver_key: str = ""  # Optional: set when using resolver_key-based lookups

    def has_minimum_history(self, min_runs: int = 14) -> bool:
        """Check if resolver has enough historical observations."""
        return self.runs_seen_30d >= min_runs


def normalize_reasons_signature(reasons: list[str]) -> str:
    unique = sorted({reason for reason in reasons if reason})
    return "|".join(unique)


def derive_dns_host_outcomes(results: list[ValidationResult]) -> list[DnsHostOutcome]:
    grouped: dict[str, list[ValidationResult]] = {}
    for result in results:
        if result.candidate.transport not in ("dns-udp", "dns-tcp"):
            continue
        grouped.setdefault(result.candidate.host, []).append(result)

    outcomes: list[DnsHostOutcome] = []
    for host, host_results in grouped.items():
        accepted_count = sum(1 for result in host_results if result.status == "accepted")
        candidate_count = sum(1 for result in host_results if result.status == "candidate")
        rejected_count = sum(1 for result in host_results if result.status == "rejected")
        udp_status = _transport_status(host_results, "dns-udp")
        tcp_status = _transport_status(host_results, "dns-tcp")

        if accepted_count > 0:
            status = "accepted"
            reasons: list[str] = []
        elif candidate_count > 0:
            status = "candidate"
            reasons = []
        else:
            status = "rejected"
            reasons = sorted({reason for result in host_results for reason in result.reasons})

        outcomes.append(
            DnsHostOutcome(
                host=host,
                status=status,
                reasons=reasons,
                reasons_signature=normalize_reasons_signature(reasons),
                accepted_count=accepted_count,
                candidate_count=candidate_count,
                rejected_count=rejected_count,
                udp_status=udp_status,
                tcp_status=tcp_status,
            )
        )
    return sorted(outcomes, key=lambda outcome: outcome.host)


def _transport_status(
    results: list[ValidationResult],
    transport: str,
) -> Status | None:
    for result in results:
        if result.candidate.transport == transport:
            return result.status
    return None


def connect_history_db(path: str | Path):
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect(str(db_path))
    ensure_history_schema(connection)
    return connection


def ensure_history_schema(connection) -> None:
    """Ensure history schema exists and rebuild cleanly on incompatibility."""
    existing_tables = _list_history_tables(connection)
    if _schema_needs_rebuild(connection, existing_tables):
        _recreate_history_schema(connection)
        return

    _create_current_schema(connection)
    _write_schema_version(connection)


def _check_schema_version(connection) -> int:
    """Check current schema version, returns 0 if no version recorded."""
    try:
        row = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
        ).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0


def _list_history_tables(connection) -> set[str]:
    rows = connection.execute(
        """
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = current_schema()
        """
    ).fetchall()
    return {row[0] for row in rows}


def _schema_needs_rebuild(connection, existing_tables: set[str]) -> bool:
    if not existing_tables:
        return False
    if existing_tables.intersection(LEGACY_HISTORY_TABLES):
        return True
    if not CURRENT_HISTORY_TABLES.issubset(existing_tables):
        return True
    return _check_schema_version(connection) != HISTORY_SCHEMA_VERSION


def _recreate_history_schema(connection) -> None:
    for table in sorted(CURRENT_HISTORY_TABLES.union(LEGACY_HISTORY_TABLES)):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    _create_current_schema(connection)
    _write_schema_version(connection)


def _create_current_schema(connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_metadata (
            key VARCHAR PRIMARY KEY,
            value VARCHAR,
            updated_at TIMESTAMP
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_host_quarantine (
            host VARCHAR PRIMARY KEY,
            first_quarantined_on DATE,
            last_quarantined_on DATE,
            retry_after DATE,
            reasons_signature VARCHAR,
            reasons_json VARCHAR,
            cycles INTEGER
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_id VARCHAR PRIMARY KEY,
            run_date DATE,
            run_started_at TIMESTAMP,
            generated_at TIMESTAMP,
            github_run_id VARCHAR,
            repo_sha VARCHAR,
            crawler_sha VARCHAR,
            run_type VARCHAR
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS resolver_run_status (
            run_id VARCHAR,
            resolver_key VARCHAR,
            host VARCHAR,
            transport VARCHAR,
            endpoint_url VARCHAR,
            port INTEGER,
            path VARCHAR,
            status VARCHAR,
            reasons_signature VARCHAR,
            reasons_json VARCHAR,
            accepted_probe_count INTEGER,
            failed_probe_count INTEGER,
            total_probe_count INTEGER,
            p50_latency_ms DOUBLE,
            p95_latency_ms DOUBLE,
            jitter_ms DOUBLE,
            PRIMARY KEY (run_id, resolver_key)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS resolver_daily (
            run_date DATE,
            resolver_key VARCHAR,
            host VARCHAR,
            transport VARCHAR,
            day_status VARCHAR,
            reasons_signature VARCHAR,
            reasons_json VARCHAR,
            runs_that_day INTEGER,
            successful_runs_that_day INTEGER,
            failed_runs_that_day INTEGER,
            flapped_within_day BOOLEAN,
            p50_latency_ms DOUBLE,
            p95_latency_ms DOUBLE,
            jitter_ms DOUBLE,
            PRIMARY KEY (run_date, resolver_key)
        )
        """
    )


def _write_schema_version(connection) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO schema_metadata (key, value, updated_at)
        VALUES ('schema_version', ?, CURRENT_TIMESTAMP)
        """,
        [str(HISTORY_SCHEMA_VERSION)],
    )


def update_history(
    connection,
    metadata: RunMetadata,
    results: list[ValidationResult],
    filtered: list[FilteredCandidate],
) -> None:
    """Update history with run-level and daily rollup data."""
    _ = filtered
    # Generate unique run_id for run-level tables
    run_id = f"{metadata.github_run_id}_{metadata.generated_at.isoformat()}"
    run_started_at = metadata.generated_at  # For now, same as generated_at

    # 1) Insert into runs
    connection.execute(
        """
        INSERT OR REPLACE INTO runs
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            run_id,
            metadata.run_date,
            run_started_at.replace(tzinfo=None),
            metadata.generated_at.replace(tzinfo=None),
            metadata.github_run_id,
            metadata.repo_sha,
            metadata.crawler_sha,
            metadata.run_type,
        ],
    )

    # 2) Insert per-resolver run status for ALL transports (including DoH)
    # First, clear any existing entries for this run_id
    connection.execute(
        "DELETE FROM resolver_run_status WHERE run_id = ?",
        [run_id],
    )

    for result in results:
        candidate = result.candidate
        resolver_key = normalize_resolver_key(candidate)

        # Count probes
        accepted_probes = sum(1 for p in result.probes if p.ok)
        failed_probes = len(result.probes) - accepted_probes

        # Get latency metrics from derived_metrics if available
        p50 = result.derived_metrics.get("p50_latency_ms")
        p95 = result.derived_metrics.get("p95_latency_ms")
        jitter = result.derived_metrics.get("jitter_ms")

        connection.execute(
            """
            INSERT INTO resolver_run_status
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                run_id,
                resolver_key,
                candidate.host,
                candidate.transport,
                candidate.endpoint_url,
                candidate.port,
                candidate.path,
                result.status,
                normalize_reasons_signature(result.reasons),
                json.dumps(result.reasons),
                accepted_probes,
                failed_probes,
                len(result.probes),
                p50,
                p95,
                jitter,
            ],
        )

    # 3) Aggregate daily rollups for this run_date
    _update_resolver_daily(connection, metadata.run_date)

    _refresh_quarantine_state(connection, metadata.run_date)
    prune_history(connection, metadata.run_date)


def _update_resolver_daily(connection, run_date: date) -> None:
    """Aggregate resolver_run_status into resolver_daily for a given date.

    Rules for day_status aggregation:
    - accepted: at least one accepted run and no severe correctness reasons
    - candidate: mixed statuses without severe correctness reasons
    - rejected: all runs rejected, or any severe correctness reason is present
    """
    connection.execute(
        "DELETE FROM resolver_daily WHERE run_date = ?",
        [run_date],
    )

    rows = connection.execute(
        """
        SELECT
            rs.resolver_key,
            rs.host,
            rs.transport,
            rs.status,
            rs.reasons_json,
            rs.p50_latency_ms,
            rs.p95_latency_ms,
            rs.jitter_ms
        FROM runs r
        JOIN resolver_run_status rs ON r.run_id = rs.run_id
        WHERE r.run_date = ?
        ORDER BY rs.resolver_key
        """,
        [run_date],
    ).fetchall()

    grouped: dict[
        str, list[tuple[str, str, str, str, str | None, float | None, float | None, float | None]]
    ] = {}
    for row in rows:
        grouped.setdefault(row[0], []).append(row)

    for resolver_rows in grouped.values():
        resolver_key = resolver_rows[0][0]
        host = resolver_rows[0][1]
        transport = resolver_rows[0][2]
        statuses = [row[3] for row in resolver_rows]
        accepted_runs = sum(1 for status in statuses if status == "accepted")
        candidate_runs = sum(1 for status in statuses if status == "candidate")
        rejected_runs = sum(1 for status in statuses if status == "rejected")
        runs_that_day = len(statuses)

        reasons: set[str] = set()
        severe_seen = False
        p50_values: list[float] = []
        p95_values: list[float] = []
        jitter_values: list[float] = []
        for _, _, _, _, reasons_json, p50, p95, jitter in resolver_rows:
            if reasons_json:
                parsed_reasons = json.loads(reasons_json)
                for reason in parsed_reasons:
                    reasons.add(reason)
                    if reason in SEVERE_CORRECTNESS_REASONS:
                        severe_seen = True
            if p50 is not None:
                p50_values.append(p50)
            if p95 is not None:
                p95_values.append(p95)
            if jitter is not None:
                jitter_values.append(jitter)

        if severe_seen:
            day_status = "rejected"
        elif accepted_runs > 0 and rejected_runs == 0:
            day_status = "accepted"
        elif rejected_runs == runs_that_day:
            day_status = "rejected"
        else:
            day_status = "candidate"

        statuses_seen = (accepted_runs > 0) + (candidate_runs > 0) + (rejected_runs > 0)
        flapped_within_day = statuses_seen > 1

        all_reasons_list = sorted(reasons)
        reasons_signature = normalize_reasons_signature(all_reasons_list)
        successful_runs = accepted_runs
        failed_runs = rejected_runs
        avg_p50 = sum(p50_values) / len(p50_values) if p50_values else None
        avg_p95 = sum(p95_values) / len(p95_values) if p95_values else None
        avg_jitter = sum(jitter_values) / len(jitter_values) if jitter_values else None

        connection.execute(
            """
            INSERT INTO resolver_daily
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                run_date,
                resolver_key,
                host,
                transport,
                day_status,
                reasons_signature,
                json.dumps(all_reasons_list),
                runs_that_day,
                successful_runs,
                failed_runs,
                flapped_within_day,
                avg_p50,
                avg_p95,
                avg_jitter,
            ],
        )


def prune_history(connection, run_date: date) -> None:
    cutoff = run_date - timedelta(days=HISTORY_RETENTION_DAYS - 1)
    connection.execute(
        """
        DELETE FROM resolver_run_status
        WHERE run_id IN (SELECT run_id FROM runs WHERE run_date < ?)
        """,
        [cutoff],
    )
    connection.execute("DELETE FROM runs WHERE run_date < ?", [cutoff])
    connection.execute("DELETE FROM resolver_daily WHERE run_date < ?", [cutoff])


def load_active_quarantines(connection, run_date: date) -> dict[str, QuarantineRecord]:
    rows = connection.execute(
        """
        SELECT host, first_quarantined_on, last_quarantined_on, retry_after,
               reasons_signature, reasons_json, cycles
        FROM dns_host_quarantine
        WHERE retry_after > ?
        """,
        [run_date],
    ).fetchall()
    return {
        row[0]: QuarantineRecord(
            host=row[0],
            first_quarantined_on=row[1],
            last_quarantined_on=row[2],
            retry_after=row[3],
            reasons_signature=row[4],
            reasons_json=row[5],
            cycles=row[6],
        )
        for row in rows
    }


def apply_dns_quarantine(
    connection,
    run_date: date,
    candidates: list[Candidate],
    filtered: list[FilteredCandidate],
) -> tuple[list[Candidate], list[FilteredCandidate]]:
    quarantines = load_active_quarantines(connection, run_date)
    eligible: list[Candidate] = []
    filtered_records = list(filtered)

    for candidate in candidates:
        if candidate.transport not in ("dns-udp", "dns-tcp"):
            eligible.append(candidate)
            continue

        quarantine = quarantines.get(candidate.host)
        if quarantine is None:
            eligible.append(candidate)
            continue

        reasons = json.loads(quarantine.reasons_json)
        detail = (
            f"historically rejected for 14 consecutive days; retry after "
            f"{quarantine.retry_after.isoformat()}; last reasons: {', '.join(reasons)}"
        )
        filtered_records.append(
            FilteredCandidate(
                candidate=candidate,
                reason="historical_dns_quarantine",
                detail=detail,
                stage="history",
            )
        )

    return eligible, filtered_records


def _refresh_quarantine_state(
    connection,
    run_date: date,
) -> None:
    outcomes = _load_dns_host_outcomes_for_day(connection, run_date)

    existing_rows = connection.execute(
        """
        SELECT host, first_quarantined_on, last_quarantined_on, retry_after,
               reasons_signature, reasons_json, cycles
        FROM dns_host_quarantine
        """
    ).fetchall()
    existing = {
        row[0]: QuarantineRecord(
            host=row[0],
            first_quarantined_on=row[1],
            last_quarantined_on=row[2],
            retry_after=row[3],
            reasons_signature=row[4],
            reasons_json=row[5],
            cycles=row[6],
        )
        for row in existing_rows
    }

    for outcome in outcomes:
        record = existing.get(outcome.host)
        if record is not None and record.retry_after <= run_date:
            if (
                outcome.status == "rejected"
                and outcome.reasons_signature == record.reasons_signature
            ):
                _upsert_quarantine(
                    connection,
                    QuarantineRecord(
                        host=outcome.host,
                        first_quarantined_on=record.first_quarantined_on,
                        last_quarantined_on=run_date,
                        retry_after=run_date + timedelta(days=DNS_QUARANTINE_DAYS),
                        reasons_signature=outcome.reasons_signature,
                        reasons_json=json.dumps(outcome.reasons),
                        cycles=record.cycles + 1,
                    ),
                )
            else:
                connection.execute("DELETE FROM dns_host_quarantine WHERE host = ?", [outcome.host])
            continue

        if record is None and _has_rejected_streak(connection, outcome.host, run_date):
            _upsert_quarantine(
                connection,
                QuarantineRecord(
                    host=outcome.host,
                    first_quarantined_on=run_date,
                    last_quarantined_on=run_date,
                    retry_after=run_date + timedelta(days=DNS_QUARANTINE_DAYS),
                    reasons_signature=outcome.reasons_signature,
                    reasons_json=json.dumps(outcome.reasons),
                    cycles=1,
                ),
            )


def _load_dns_host_outcomes_for_day(connection, run_date: date) -> list[DnsHostOutcome]:
    rows = connection.execute(
        """
        SELECT host, day_status, reasons_json
        FROM resolver_daily
        WHERE run_date = ?
          AND transport IN ('dns-udp', 'dns-tcp')
        """,
        [run_date],
    ).fetchall()

    grouped: dict[str, list[tuple[str, str | None]]] = {}
    for host, day_status, reasons_json in rows:
        grouped.setdefault(host, []).append((day_status, reasons_json))

    outcomes: list[DnsHostOutcome] = []
    for host, host_rows in grouped.items():
        statuses = [row[0] for row in host_rows]
        if "accepted" in statuses:
            status: Status = "accepted"
        elif "candidate" in statuses:
            status = "candidate"
        else:
            status = "rejected"

        reasons: set[str] = set()
        for _, reasons_json in host_rows:
            if reasons_json:
                reasons.update(json.loads(reasons_json))
        normalized_reasons = sorted(reasons)
        outcomes.append(
            DnsHostOutcome(
                host=host,
                status=status,
                reasons=normalized_reasons,
                reasons_signature=normalize_reasons_signature(normalized_reasons),
                accepted_count=statuses.count("accepted"),
                candidate_count=statuses.count("candidate"),
                rejected_count=statuses.count("rejected"),
                udp_status=None,
                tcp_status=None,
            )
        )

    return sorted(outcomes, key=lambda outcome: outcome.host)


def _has_rejected_streak(connection, host: str, run_date: date) -> bool:
    """Check if host has been rejected for DNS_QUARANTINE_STREAK_DAYS consecutive days.

    Aggregates resolver_daily entries by host (for plain DNS transports only).
    """
    # Aggregate resolver_daily by host, only considering DNS transports
    rows = connection.execute(
        """
        SELECT run_date,
               CASE
                   WHEN SUM(CASE WHEN day_status = 'accepted' THEN 1 ELSE 0 END) > 0
                       THEN 'accepted'
                   WHEN SUM(CASE WHEN day_status = 'candidate' THEN 1 ELSE 0 END) > 0
                       THEN 'candidate'
                   ELSE 'rejected'
               END as aggregated_status
        FROM resolver_daily
        WHERE host = ?
          AND transport IN ('dns-udp', 'dns-tcp')
          AND run_date <= ?
        GROUP BY run_date
        ORDER BY run_date DESC
        LIMIT ?
        """,
        [host, run_date, DNS_QUARANTINE_STREAK_DAYS],
    ).fetchall()

    if len(rows) != DNS_QUARANTINE_STREAK_DAYS:
        return False

    for offset, (row_date, status) in enumerate(rows):
        expected_date = run_date - timedelta(days=offset)
        if row_date != expected_date or status != "rejected":
            return False
    return True


def _upsert_quarantine(connection, record: QuarantineRecord) -> None:
    connection.execute(
        """
        INSERT OR REPLACE INTO dns_host_quarantine VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            record.host,
            record.first_quarantined_on,
            record.last_quarantined_on,
            record.retry_after,
            record.reasons_signature,
            record.reasons_json,
            record.cycles,
        ],
    )


def parse_generated_at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def read_run_metadata(
    build_meta_path: str | Path,
    crawler_sha: str,
) -> RunMetadata:
    payload = json.loads(Path(build_meta_path).read_text(encoding="utf-8"))
    generated_at = parse_generated_at(payload["generated_at"])
    return RunMetadata(
        run_date=generated_at.date(),
        generated_at=generated_at,
        github_run_id=str(payload["run_id"]),
        repo_sha=str(payload["sha"]),
        crawler_sha=crawler_sha.strip(),
    )


def compute_latest_summary(connection) -> dict[str, Any]:
    """Compute summary statistics from the current history schema."""
    latest_run = connection.execute(
        """
        SELECT run_date, github_run_id
        FROM runs
        ORDER BY run_date DESC, run_started_at DESC
        LIMIT 1
        """
    ).fetchone()

    if latest_run is None:
        return {
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

    run_date = latest_run[0]
    run_id = latest_run[1]

    # Count runs tracked
    runs_tracked = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]

    # Get resolver counts for latest run
    status_counts = connection.execute(
        """
        SELECT
            SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) as accepted,
            SUM(CASE WHEN status = 'candidate' THEN 1 ELSE 0 END) as candidate,
            SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) as rejected
        FROM resolver_run_status
        WHERE run_id = (SELECT run_id FROM runs
                      ORDER BY run_date DESC, run_started_at DESC LIMIT 1)
        """
    ).fetchone()

    accepted_count = status_counts[0] or 0
    candidate_count = status_counts[1] or 0
    rejected_count = status_counts[2] or 0

    # Quarantined count
    quarantined_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM dns_host_quarantine
        WHERE retry_after > ?
        """,
        [run_date],
    ).fetchone()[0]

    # Top reasons from resolver_daily
    reason_counts: dict[str, int] = {}
    rejected_rows = connection.execute(
        """
        SELECT reasons_json
        FROM resolver_daily
        WHERE day_status = 'rejected'
        """
    ).fetchall()
    for (reasons_json,) in rejected_rows:
        if reasons_json:
            for reason in json.loads(reasons_json):
                reason_counts[reason] = reason_counts.get(reason, 0) + 1

    top_reasons = sorted(reason_counts.items(), key=lambda item: (-item[1], item[0]))[:5]

    return {
        "latest_run_date": run_date.isoformat(),
        "latest_run_id": run_id,
        "runs_tracked": runs_tracked,
        "accepted_count": accepted_count,
        "candidate_count": candidate_count,
        "rejected_count": rejected_count,
        "filtered_count": 0,  # Not tracked per-run yet
        "accepted_delta": 0,  # Would need historical comparison
        "rejected_delta": 0,
        "quarantined_count": quarantined_count,
        "top_reasons": top_reasons,
        "schema_version": HISTORY_SCHEMA_VERSION,
    }


def get_resolver_stability_metrics(
    connection,
    resolver_key: str,
    run_date: date,
) -> ResolverStabilityMetrics | None:
    """Compute stability metrics for a resolver from historical data.

    Reads from resolver_daily table using endpoint-level resolver_key.
    Returns None if no history exists for this resolver.
    """
    cutoff_7d = run_date - timedelta(days=7)
    cutoff_30d = run_date - timedelta(days=30)

    # Get 7-day stats (count distinct days, not runs)
    row_7d = connection.execute(
        """
        SELECT COUNT(*), SUM(CASE WHEN day_status = 'accepted' THEN 1 ELSE 0 END)
        FROM resolver_daily
        WHERE resolver_key = ? AND run_date > ? AND run_date <= ?
        """,
        [resolver_key, cutoff_7d, run_date],
    ).fetchone()

    # Get 30-day stats (count distinct days, not runs)
    row_30d = connection.execute(
        """
        SELECT COUNT(*), SUM(CASE WHEN day_status = 'accepted' THEN 1 ELSE 0 END)
        FROM resolver_daily
        WHERE resolver_key = ? AND run_date > ? AND run_date <= ?
        """,
        [resolver_key, cutoff_30d, run_date],
    ).fetchone()

    if row_30d is None or row_30d[0] == 0:
        # No history at all for this resolver_key
        return None

    runs_seen_7d = row_7d[0] if row_7d else 0
    success_days_7d = row_7d[1] if row_7d and row_7d[1] else 0
    runs_seen_30d = row_30d[0]
    success_days_30d = row_30d[1] if row_30d[1] else 0

    # Parse resolver_key to get transport and host
    transport, host, _ = parse_resolver_key(resolver_key)

    # Get consecutive success/fail streaks by scanning from most recent
    consecutive_rows = connection.execute(
        """
        SELECT run_date, day_status
        FROM resolver_daily
        WHERE resolver_key = ? AND run_date <= ?
        ORDER BY run_date DESC
        """,
        [resolver_key, run_date],
    ).fetchall()

    consecutive_success_days = 0
    consecutive_fail_days = 0
    latest_status = None

    for i, (row_date, status) in enumerate(consecutive_rows):
        if i == 0:
            latest_status = status
        expected_date = run_date - timedelta(days=i)
        if row_date != expected_date:
            # Gap in history, stop counting
            break
        if status == "accepted":
            if consecutive_fail_days == 0:
                consecutive_success_days += 1
            else:
                break
        elif status == "rejected":
            if consecutive_success_days == 0:
                consecutive_fail_days += 1
            else:
                break
        else:  # candidate - neutral, break the streak
            break

    # Count status flaps in last 30 days (day-to-day transitions)
    status_flaps = 0
    prev_status = None
    for _, status in consecutive_rows[:30]:
        if prev_status is not None:
            # Count transitions between accepted/candidate/rejected
            if status != prev_status:
                status_flaps += 1
        prev_status = status

    # Count days with intra-day flapping
    flapped_within_day_7d = 0
    flapped_within_day_30d = 0

    flap_rows = connection.execute(
        """
        SELECT run_date, flapped_within_day
        FROM resolver_daily
        WHERE resolver_key = ? AND run_date <= ?
        ORDER BY run_date DESC
        LIMIT 30
        """,
        [resolver_key, run_date],
    ).fetchall()

    for row_date, flapped in flap_rows:
        if flapped:
            flapped_within_day_30d += 1
            if row_date > cutoff_7d:
                flapped_within_day_7d += 1

    return ResolverStabilityMetrics(
        host=host,
        transport=transport,
        resolver_key=resolver_key,
        runs_seen_7d=runs_seen_7d,
        runs_seen_30d=runs_seen_30d,
        success_days_7d=success_days_7d,
        success_days_30d=success_days_30d,
        consecutive_success_days=consecutive_success_days,
        consecutive_fail_days=consecutive_fail_days,
        status_flaps_30d=status_flaps,
        latest_status=latest_status,
        flapped_within_day_7d=flapped_within_day_7d,
        flapped_within_day_30d=flapped_within_day_30d,
    )
