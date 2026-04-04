from __future__ import annotations

import argparse
from pathlib import Path

from resolver_inventory.history import connect_history_db, read_run_metadata, update_history
from resolver_inventory.serialization import (
    filtered_candidate_from_dict,
    load_json_list,
    validation_result_from_dict,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history-db", required=True)
    parser.add_argument("--validated-input", required=True)
    parser.add_argument("--filtered-input", required=True)
    parser.add_argument("--meta-build", required=True)
    parser.add_argument("--crawler-sha-file", required=True)
    args = parser.parse_args()

    metadata = read_run_metadata(
        args.meta_build,
        Path(args.crawler_sha_file).read_text(encoding="utf-8").strip(),
    )
    results = [
        validation_result_from_dict(record) for record in load_json_list(args.validated_input)
    ]
    filtered = [
        filtered_candidate_from_dict(record) for record in load_json_list(args.filtered_input)
    ]

    with connect_history_db(args.history_db) as connection:
        update_history(connection, metadata, results, filtered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
