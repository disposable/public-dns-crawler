"""Disk-backed storage for intermediate validation probe results."""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

from resolver_inventory.models import ProbeResult


def probe_result_to_dict(probe: ProbeResult) -> dict[str, object]:
    return {
        "ok": probe.ok,
        "probe": probe.probe,
        "latency_ms": probe.latency_ms,
        "error": probe.error,
        "details": probe.details,
    }


def probe_result_from_dict(data: dict[str, object]) -> ProbeResult:
    return ProbeResult(
        ok=bool(data["ok"]),
        probe=str(data["probe"]),
        latency_ms=None if data.get("latency_ms") is None else float(data["latency_ms"]),
        error=None if data.get("error") is None else str(data["error"]),
        details={str(k): str(v) for k, v in dict(data.get("details", {})).items()},
    )


class ValidationStateStore:
    def __init__(self) -> None:
        tmp = tempfile.NamedTemporaryFile(
            prefix="resolver-inventory-state-",
            suffix=".sqlite3",
            delete=False,
        )
        tmp.close()
        self.path = Path(tmp.name)
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=OFF")
        self.conn.execute("PRAGMA temp_store=MEMORY")
        self.conn.execute(
            """
            CREATE TABLE probe_results (
                candidate_idx INTEGER NOT NULL,
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            "CREATE INDEX probe_results_candidate_idx_idx ON probe_results(candidate_idx)"
        )
        self.conn.commit()

    def append_probe_result(self, candidate_idx: int, probe: ProbeResult) -> None:
        self.conn.execute(
            "INSERT INTO probe_results(candidate_idx, payload) VALUES(?, ?)",
            (
                candidate_idx,
                json.dumps(
                    probe_result_to_dict(probe),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            ),
        )

    def load_probe_results(self, candidate_idx: int) -> list[ProbeResult]:
        rows = self.conn.execute(
            "SELECT payload FROM probe_results WHERE candidate_idx = ? ORDER BY seq",
            (candidate_idx,),
        ).fetchall()
        return [probe_result_from_dict(json.loads(row[0])) for row in rows]

    def delete_candidate(self, candidate_idx: int) -> None:
        self.conn.execute("DELETE FROM probe_results WHERE candidate_idx = ?", (candidate_idx,))

    def close(self) -> None:
        try:
            self.conn.commit()
        finally:
            self.conn.close()
            self.path.unlink(missing_ok=True)
