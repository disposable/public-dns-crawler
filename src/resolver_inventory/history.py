"""Historical run memory and DNS quarantine helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import duckdb

from resolver_inventory.models import Candidate, DnsHostOutcome, FilteredCandidate, ValidationResult

HISTORY_RETENTION_DAYS = 30
DNS_QUARANTINE_STREAK_DAYS = 14
DNS_QUARANTINE_DAYS = 90


@dataclass(slots=True)
class RunMetadata:
    run_date: date
    generated_at: datetime
    github_run_id: str
    repo_sha: str
    crawler_sha: str


@dataclass(slots=True)
class QuarantineRecord:
    host: str
    first_quarantined_on: date
    last_quarantined_on: date
    retry_after: date
    reasons_signature: str
    reasons_json: str
    cycles: int


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
):
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
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS runs (
            run_date DATE PRIMARY KEY,
            generated_at TIMESTAMP,
            github_run_id VARCHAR,
            repo_sha VARCHAR,
            crawler_sha VARCHAR
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS run_stats (
            run_date DATE PRIMARY KEY,
            accepted_count INTEGER,
            candidate_count INTEGER,
            rejected_count INTEGER,
            filtered_count INTEGER
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS dns_host_daily (
            run_date DATE,
            host VARCHAR,
            status VARCHAR,
            reasons_signature VARCHAR,
            reasons_json VARCHAR,
            accepted_count INTEGER,
            candidate_count INTEGER,
            rejected_count INTEGER,
            udp_status VARCHAR,
            tcp_status VARCHAR,
            PRIMARY KEY (run_date, host)
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


def update_history(
    connection,
    metadata: RunMetadata,
    results: list[ValidationResult],
    filtered: list[FilteredCandidate],
) -> None:
    accepted_count = sum(1 for result in results if result.status == "accepted")
    candidate_count = sum(1 for result in results if result.status == "candidate")
    rejected_count = sum(1 for result in results if result.status == "rejected")

    connection.execute(
        """
        INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?)
        """,
        [
            metadata.run_date,
            metadata.generated_at.replace(tzinfo=None),
            metadata.github_run_id,
            metadata.repo_sha,
            metadata.crawler_sha,
        ],
    )
    connection.execute(
        """
        INSERT OR REPLACE INTO run_stats VALUES (?, ?, ?, ?, ?)
        """,
        [
            metadata.run_date,
            accepted_count,
            candidate_count,
            rejected_count,
            len(filtered),
        ],
    )

    outcomes = derive_dns_host_outcomes(results)
    connection.execute("DELETE FROM dns_host_daily WHERE run_date = ?", [metadata.run_date])
    for outcome in outcomes:
        connection.execute(
            """
            INSERT INTO dns_host_daily VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                metadata.run_date,
                outcome.host,
                outcome.status,
                outcome.reasons_signature,
                json.dumps(outcome.reasons),
                outcome.accepted_count,
                outcome.candidate_count,
                outcome.rejected_count,
                outcome.udp_status,
                outcome.tcp_status,
            ],
        )

    _refresh_quarantine_state(connection, metadata.run_date, outcomes)
    prune_history(connection, metadata.run_date)


def prune_history(connection, run_date: date) -> None:
    cutoff = run_date - timedelta(days=HISTORY_RETENTION_DAYS - 1)
    connection.execute("DELETE FROM runs WHERE run_date < ?", [cutoff])
    connection.execute("DELETE FROM run_stats WHERE run_date < ?", [cutoff])
    connection.execute("DELETE FROM dns_host_daily WHERE run_date < ?", [cutoff])


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
    outcomes: list[DnsHostOutcome],
) -> None:
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


def _has_rejected_streak(connection, host: str, run_date: date) -> bool:
    rows = connection.execute(
        """
        SELECT run_date, status
        FROM dns_host_daily
        WHERE host = ? AND run_date <= ?
        ORDER BY run_date DESC
        LIMIT ?
        """,
        [host, run_date, DNS_QUARANTINE_STREAK_DAYS],
    ).fetchall()
    if len(rows) != DNS_QUARANTINE_STREAK_DAYS:
        return False

    for offset, row in enumerate(rows):
        expected_date = run_date - timedelta(days=offset)
        if row[0] != expected_date or row[1] != "rejected":
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
    latest_run = connection.execute(
        """
        SELECT r.run_date, r.github_run_id, s.accepted_count, s.candidate_count,
               s.rejected_count, s.filtered_count
        FROM runs r
        JOIN run_stats s USING (run_date)
        ORDER BY r.run_date DESC
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

    oldest_run = connection.execute(
        """
        SELECT accepted_count, rejected_count
        FROM run_stats
        ORDER BY run_date ASC
        LIMIT 1
        """
    ).fetchone()
    runs_tracked = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
    quarantined_count = connection.execute(
        """
        SELECT COUNT(*)
        FROM dns_host_quarantine
        WHERE retry_after > ?
        """,
        [latest_run[0]],
    ).fetchone()[0]

    reason_counts: dict[str, int] = {}
    rejected_rows = connection.execute(
        """
        SELECT reasons_json
        FROM dns_host_daily
        WHERE status = 'rejected'
        """
    ).fetchall()
    for (reasons_json,) in rejected_rows:
        for reason in json.loads(reasons_json):
            reason_counts[reason] = reason_counts.get(reason, 0) + 1

    top_reasons = sorted(reason_counts.items(), key=lambda item: (-item[1], item[0]))[:5]
    return {
        "latest_run_date": latest_run[0].isoformat(),
        "latest_run_id": latest_run[1],
        "runs_tracked": runs_tracked,
        "accepted_count": latest_run[2],
        "candidate_count": latest_run[3],
        "rejected_count": latest_run[4],
        "filtered_count": latest_run[5],
        "accepted_delta": latest_run[2] - oldest_run[0],
        "rejected_delta": latest_run[4] - oldest_run[1],
        "quarantined_count": quarantined_count,
        "top_reasons": top_reasons,
    }
