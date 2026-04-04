"""Timing utilities."""

from __future__ import annotations

import time
from collections.abc import Generator
from contextlib import contextmanager


@contextmanager
def measure_ms() -> Generator[list[float]]:
    """Context manager that appends elapsed milliseconds into the provided list."""
    result: list[float] = []
    start = time.perf_counter()
    try:
        yield result
    finally:
        result.append((time.perf_counter() - start) * 1000.0)
