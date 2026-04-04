from __future__ import annotations

import argparse
from datetime import date
from pathlib import Path

from resolver_inventory.export.json import export_filtered_json
from resolver_inventory.history import apply_dns_quarantine, connect_history_db
from resolver_inventory.serialization import (
    candidate_from_dict,
    candidate_to_dict,
    filtered_candidate_from_dict,
    load_json_list,
    write_json,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history-db", required=True)
    parser.add_argument("--run-date", required=True)
    parser.add_argument("--candidates-input", required=True)
    parser.add_argument("--filtered-input", required=True)
    parser.add_argument("--candidates-output", required=True)
    parser.add_argument("--filtered-output", required=True)
    args = parser.parse_args()

    candidates = [candidate_from_dict(record) for record in load_json_list(args.candidates_input)]
    filtered = [
        filtered_candidate_from_dict(record) for record in load_json_list(args.filtered_input)
    ]

    history_path = Path(args.history_db)
    if history_path.exists():
        with connect_history_db(history_path) as connection:
            candidates, filtered = apply_dns_quarantine(
                connection,
                date.fromisoformat(args.run_date),
                candidates,
                filtered,
            )

    write_json(args.candidates_output, [candidate_to_dict(candidate) for candidate in candidates])
    export_filtered_json(filtered, path=args.filtered_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
