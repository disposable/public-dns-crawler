from __future__ import annotations

import argparse
import glob
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
    parser.add_argument("--validated-input")
    parser.add_argument("--accepted-input")
    parser.add_argument("--candidate-input")
    parser.add_argument("--rejected-input")
    parser.add_argument("--filtered-input", required=True)
    parser.add_argument("--meta-build", required=True)
    parser.add_argument("--crawler-sha-file", required=True)
    args = parser.parse_args()

    metadata = read_run_metadata(
        args.meta_build,
        Path(args.crawler_sha_file).read_text(encoding="utf-8").strip(),
    )
    results = []
    if args.validated_input:
        results.extend(_load_validation_results(args.validated_input))
    else:
        if not args.accepted_input or not args.rejected_input:
            parser.error(
                "either --validated-input or both --accepted-input and "
                "--rejected-input are required"
            )
        results.extend(_load_validation_results(args.accepted_input))
        if args.candidate_input:
            results.extend(_load_validation_results(args.candidate_input))
        results.extend(_load_validation_results(args.rejected_input))
    filtered = [
        filtered_candidate_from_dict(record) for record in load_json_list(args.filtered_input)
    ]

    print(
        "update_history: "
        f"results={len(results)} filtered={len(filtered)} history_db={args.history_db}",
        flush=True,
    )

    with connect_history_db(args.history_db) as connection:
        update_history(connection, metadata, results, filtered)

    print("update_history: done", flush=True)

    return 0


def _load_validation_results(path: str) -> list:
    file_path = Path(path)
    if file_path.exists():
        return [validation_result_from_dict(record) for record in load_json_list(file_path)]

    stem = file_path.stem
    suffix = file_path.suffix or ".json"
    part_paths = sorted(glob.glob(str(file_path.with_name(f"{stem}.part-*{suffix}"))))
    if not part_paths:
        raise FileNotFoundError(path)
    records = []
    for part_path in part_paths:
        records.extend(validation_result_from_dict(record) for record in load_json_list(part_path))
    return records


if __name__ == "__main__":
    raise SystemExit(main())
