"""README report generation for historical run stats."""

from __future__ import annotations

from pathlib import Path

from resolver_inventory.history import compute_latest_summary

GENERATED_STATS_START = "<!-- GENERATED_STATS_START -->"
GENERATED_STATS_END = "<!-- GENERATED_STATS_END -->"


def render_stats_section(summary: dict) -> str:
    latest_run_date = summary["latest_run_date"] or "n/a"
    latest_run_id = summary["latest_run_id"] or "n/a"
    top_reasons = summary["top_reasons"]

    lines = [
        GENERATED_STATS_START,
        "## 30-Day Validation Stats",
        "",
        f"- Latest run: `{latest_run_date}` (`run_id={latest_run_id}`)",
        f"- Runs tracked: `{summary['runs_tracked']}`",
        (
            f"- Latest totals: `{summary['accepted_count']}` accepted, "
            f"`{summary['candidate_count']}` candidate, "
            f"`{summary['rejected_count']}` rejected, "
            f"`{summary['filtered_count']}` filtered"
        ),
        (
            f"- 30-day trend: accepted `{summary['accepted_delta']:+d}`, "
            f"rejected `{summary['rejected_delta']:+d}`"
        ),
        f"- Currently quarantined DNS hosts: `{summary['quarantined_count']}`",
        "",
        "### Top Rejection Reasons",
        "",
    ]

    if top_reasons:
        lines.extend(
            [
                "| Reason | Count |",
                "| --- | ---: |",
            ]
        )
        for reason, count in top_reasons:
            lines.append(f"| `{reason}` | {count} |")
    else:
        lines.append("No rejected DNS history has been recorded yet.")

    lines.extend(
        [
            "",
            (
                "Hosts that are `rejected` for 14 consecutive daily runs are quarantined "
                "for 90 days before they are tested again."
            ),
            GENERATED_STATS_END,
        ]
    )
    return "\n".join(lines)


def replace_generated_section(readme_text: str, generated_section: str) -> str:
    if GENERATED_STATS_START in readme_text and GENERATED_STATS_END in readme_text:
        start = readme_text.index(GENERATED_STATS_START)
        end = readme_text.index(GENERATED_STATS_END) + len(GENERATED_STATS_END)
        return readme_text[:start] + generated_section + readme_text[end:]

    trimmed = readme_text.rstrip()
    return f"{trimmed}\n\n{generated_section}\n"


def update_readme_report(connection, readme_path: str | Path) -> None:
    readme = Path(readme_path)
    summary = compute_latest_summary(connection)
    updated = replace_generated_section(
        readme.read_text(encoding="utf-8"), render_stats_section(summary)
    )
    readme.write_text(updated, encoding="utf-8")
