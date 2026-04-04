"""Shared pytest configuration and fixtures."""

from __future__ import annotations

import pytest


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: starts local DNS/DoH fixtures (no public network)",
    )
    config.addinivalue_line(
        "markers",
        "network: touches the public network; excluded from required CI",
    )
