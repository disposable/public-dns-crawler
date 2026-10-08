"""Write meta/changelog.json diffing the two most recent validation runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from resolver_inventory.history import compute_changelog, connect_history_db


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history-db", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with connect_history_db(args.history_db) as connection:
        changelog = compute_changelog(connection)

    if changelog is None:
        print("generate_changelog: fewer than two runs recorded; nothing to diff")
        return 0

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(changelog, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        "generate_changelog: "
        f"+{changelog['added_count']} -{changelog['removed_count']} "
        f"{changelog['status_changes_total']} status changes -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
