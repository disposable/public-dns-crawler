"""Integration tests for historical DNS quarantine and README reporting."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from resolver_inventory.history import apply_dns_quarantine, connect_history_db, update_history
from resolver_inventory.models import Candidate, ProbeResult, ValidationResult
from resolver_inventory.readme_report import update_readme_report

pytestmark = pytest.mark.integration


def _metadata(day: date):
    from resolver_inventory.history import RunMetadata

    generated_at = datetime.combine(day, datetime.min.time(), tzinfo=UTC)
    return RunMetadata(
        run_date=day,
        generated_at=generated_at,
        github_run_id=f"run-{day.isoformat()}",
        repo_sha="repo-sha",
        crawler_sha="crawler-sha",
    )


def _dns_result(host: str, transport: str, status: str, reasons: list[str] | None = None):
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


class TestHistoricalPipeline:
    def test_quarantine_filters_candidates_and_updates_readme(self, tmp_path) -> None:
        db_path = tmp_path / "history.duckdb"
        readme_path = tmp_path / "README.md"
        readme_path.write_text(
            "# Title\n\n<!-- GENERATED_STATS_START -->\nold\n<!-- GENERATED_STATS_END -->\n",
            encoding="utf-8",
        )
        quarantined_host = "192.0.2.50"

        with connect_history_db(db_path) as connection:
            for day_offset in range(14):
                day = date(2026, 4, 1) + timedelta(days=day_offset)
                update_history(
                    connection,
                    _metadata(day),
                    [
                        _dns_result(quarantined_host, "dns-udp", "rejected", ["timeout_rate_high"]),
                        _dns_result(quarantined_host, "dns-tcp", "rejected", ["timeout_rate_high"]),
                    ],
                    [],
                )

            candidates, filtered = apply_dns_quarantine(
                connection,
                date(2026, 4, 14),
                [
                    Candidate(
                        provider=None,
                        source="test",
                        transport="dns-udp",
                        endpoint_url=None,
                        host=quarantined_host,
                        port=53,
                        path=None,
                    ),
                    Candidate(
                        provider=None,
                        source="test",
                        transport="dns-udp",
                        endpoint_url=None,
                        host="192.0.2.99",
                        port=53,
                        path=None,
                    ),
                ],
                [],
            )

            assert [candidate.host for candidate in candidates] == ["192.0.2.99"]
            assert filtered[0].reason == "historical_dns_quarantine"

            update_history(
                connection,
                _metadata(date(2026, 4, 14)),
                [_dns_result("192.0.2.99", "dns-udp", "accepted")],
                filtered,
            )
            update_readme_report(connection, readme_path)

        readme_text = readme_path.read_text(encoding="utf-8")
        assert "30-Day Validation Stats" in readme_text
        assert "Currently quarantined DNS hosts" in readme_text
