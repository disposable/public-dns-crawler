"""Timing utilities."""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime


@contextmanager
def measure_ms() -> Generator[list[float]]:
    """Context manager that appends elapsed milliseconds into the provided list."""
    result: list[float] = []
    start = time.perf_counter()
    try:
        yield result
    finally:
        result.append((time.perf_counter() - start) * 1000.0)


def utc_now_iso() -> str:
    """Return a compact UTC timestamp suitable for generated artifacts."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
