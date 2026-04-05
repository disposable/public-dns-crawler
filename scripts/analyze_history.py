#!/usr/bin/env python3
"""Analyze history DB and print diagnostics.

This script inspects the history database and prints:
- Resolver count by transport in resolver_daily
- How many DoH resolvers have history
- How many resolvers have 7d / 14d / 30d history
- Sample rows for a resolver_key
- Percentage of accepted resolvers still capped for insufficient history
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from resolver_inventory.history import (
    HISTORY_SCHEMA_VERSION,
    connect_history_db,
    get_resolver_stability_metrics,
)


def analyze_history(db_path: Path) -> dict:
    """Analyze history DB and return statistics."""
    stats = {
        "schema_version": None,
        "resolver_daily": {},
        "transport_breakdown": {},
        "history_depth": {
            "7d": 0,
            "14d": 0,
            "30d": 0,
        },
        "capped_for_insufficient_history": 0,
        "doh_with_history": 0,
        "total_accepted_in_latest": 0,
    }

    with connect_history_db(db_path) as conn:
        # Check schema version
        try:
            row = conn.execute(
                "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
            ).fetchone()
            stats["schema_version"] = int(row[0]) if row else "unknown"
        except Exception:
            stats["schema_version"] = "legacy (no metadata table)"

        # Transport breakdown
        transport_rows = conn.execute(
            """
            SELECT transport, COUNT(DISTINCT resolver_key)
            FROM resolver_daily
            GROUP BY transport
            """
        ).fetchall()
        for transport, count in transport_rows:
            stats["transport_breakdown"][transport] = count

        # DoH resolvers with history
        doh_count = conn.execute(
            """
            SELECT COUNT(DISTINCT resolver_key)
            FROM resolver_daily
            WHERE transport = 'doh'
            """
        ).fetchone()
        stats["doh_with_history"] = doh_count[0] if doh_count else 0

        # History depth analysis
        # Get latest date
        latest_row = conn.execute("SELECT MAX(run_date) FROM resolver_daily").fetchone()
        if latest_row and latest_row[0]:
            latest_date = latest_row[0]
            from datetime import timedelta

            cutoff_7d = latest_date - timedelta(days=7)
            cutoff_14d = latest_date - timedelta(days=14)
            cutoff_30d = latest_date - timedelta(days=30)

            # Count resolvers with at least 7 days of history
            row_7d = conn.execute(
                """
                SELECT COUNT(DISTINCT resolver_key)
                FROM resolver_daily
                WHERE run_date > ?
                """,
                [cutoff_7d],
            ).fetchone()
            stats["history_depth"]["7d"] = row_7d[0] if row_7d else 0

            # Count resolvers with at least 14 days of history
            row_14d = conn.execute(
                """
                SELECT COUNT(DISTINCT resolver_key)
                FROM resolver_daily
                WHERE run_date > ?
                """,
                [cutoff_14d],
            ).fetchone()
            stats["history_depth"]["14d"] = row_14d[0] if row_14d else 0

            # Count resolvers with at least 30 days of history
            row_30d = conn.execute(
                """
                SELECT COUNT(DISTINCT resolver_key)
                FROM resolver_daily
                WHERE run_date > ?
                """,
                [cutoff_30d],
            ).fetchone()
            stats["history_depth"]["30d"] = row_30d[0] if row_30d else 0

            # Check capped resolvers
            # Get resolvers accepted in latest run but with < 14 days history
            accepted_resolvers = conn.execute(
                """
                SELECT resolver_key
                FROM resolver_daily
                WHERE run_date = ? AND day_status = 'accepted'
                """,
                [latest_date],
            ).fetchall()

            stats["total_accepted_in_latest"] = len(accepted_resolvers)

            for (resolver_key,) in accepted_resolvers:
                metrics = get_resolver_stability_metrics(conn, resolver_key, latest_date)
                if metrics and metrics.runs_seen_30d < 14:
                    stats["capped_for_insufficient_history"] += 1

    return stats


def print_sample_resolver(db_path: Path, resolver_key: str | None = None) -> None:
    """Print sample rows for a resolver."""
    with connect_history_db(db_path) as conn:
        if resolver_key is None:
            # Pick a random resolver
            row = conn.execute(
                """
                SELECT resolver_key FROM resolver_daily
                ORDER BY RANDOM() LIMIT 1
                """
            ).fetchone()
            if row is None:
                print("No resolvers in history DB")
                return
            resolver_key = row[0]

        print(f"\nSample resolver: {resolver_key}")
        print("-" * 60)

        # Get latest date
        latest_row = conn.execute("SELECT MAX(run_date) FROM resolver_daily").fetchone()
        if not latest_row or not latest_row[0]:
            print("No history data")
            return
        latest_date = latest_row[0]

        if not resolver_key:
            print("No resolver key available")
            return

        resolver_key = str(resolver_key)

        # Get stability metrics
        from resolver_inventory.history import parse_resolver_key

        metrics = get_resolver_stability_metrics(conn, resolver_key, latest_date)
        if metrics:
            transport, host, _ = parse_resolver_key(resolver_key)
            print(f"Host: {host}")
            print(f"Transport: {transport}")
            print(f"Latest status: {metrics.latest_status}")
            print(f"Days seen (7d/30d): {metrics.runs_seen_7d}/{metrics.runs_seen_30d}")
            print(f"Success days (7d/30d): {metrics.success_days_7d}/{metrics.success_days_30d}")
            print(
                f"Consecutive success/fail: "
                f"{metrics.consecutive_success_days}/{metrics.consecutive_fail_days}"
            )
            print(f"Status flaps (30d): {metrics.status_flaps_30d}")
            print(
                f"Within-day flaps (7d/30d): "
                f"{metrics.flapped_within_day_7d}/{metrics.flapped_within_day_30d}"
            )
        else:
            print("No metrics available")

        print("\nRecent history (last 7 days):")
        print("-" * 60)
        rows = conn.execute(
            """
            SELECT run_date, day_status, runs_that_day, flapped_within_day
            FROM resolver_daily
            WHERE resolver_key = ?
            ORDER BY run_date DESC
            LIMIT 7
            """,
            [resolver_key],
        ).fetchall()
        for row in rows:
            print(f"  {row[0]}: {row[1]} (runs: {row[2]}, flapped: {row[3]})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze resolver history database")
    parser.add_argument("--history-db", required=True, help="Path to history.duckdb")
    parser.add_argument(
        "--sample-resolver",
        help="Show sample data for specific resolver_key (or 'random' for random)",
    )
    parser.add_argument("--json", action="store_true", help="Output stats as JSON")
    args = parser.parse_args()

    db_path = Path(args.history_db)
    if not db_path.exists():
        print(f"History DB not found: {db_path}", file=sys.stderr)
        return 1

    # Print sample resolver if requested
    if args.sample_resolver:
        resolver_key = None if args.sample_resolver == "random" else args.sample_resolver
        print_sample_resolver(db_path, resolver_key)
        return 0

    # Analyze and print stats
    stats = analyze_history(db_path)

    if args.json:
        print(json.dumps(stats, indent=2))
        return 0

    # Human-readable output
    print("=" * 60)
    print("History Database Analysis")
    print("=" * 60)
    print(f"\nSchema version: {stats['schema_version']}")
    print(f"(Target version: {HISTORY_SCHEMA_VERSION})")

    print("\nTransport Breakdown (resolver_daily):")
    print("-" * 60)
    for transport, count in sorted(stats["transport_breakdown"].items()):
        print(f"  {transport}: {count}")

    print(f"\nDoH resolvers with history: {stats['doh_with_history']}")

    print("\nHistory Depth (unique resolvers with at least N days):")
    print("-" * 60)
    for period, count in sorted(stats["history_depth"].items()):
        print(f"  {period}: {count}")

    print("\nScore Caps Analysis:")
    print("-" * 60)
    accepted = stats["total_accepted_in_latest"]
    capped = stats["capped_for_insufficient_history"]
    if accepted > 0:
        pct = (capped / accepted) * 100
        print(f"  Accepted in latest run: {accepted}")
        print(f"  Capped for insufficient history (<14 days): {capped}")
        print(f"  Percentage capped: {pct:.1f}%")
    else:
        print("  No accepted resolvers in latest run")

    print("\n" + "=" * 60)
    print("Use --sample-resolver=random to see sample resolver data")
    print("Use --sample-resolver=<resolver_key> for specific resolver")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
