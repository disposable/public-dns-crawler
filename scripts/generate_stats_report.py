from __future__ import annotations

import argparse

from resolver_inventory.history import connect_history_db
from resolver_inventory.readme_report import update_readme_report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history-db", required=True)
    parser.add_argument("--readme", required=True)
    args = parser.parse_args()

    with connect_history_db(args.history_db) as connection:
        update_readme_report(connection, args.readme)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
