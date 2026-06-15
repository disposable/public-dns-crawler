"""Unit tests for the retry helper."""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from resolver_inventory.util.retry import DEFAULT_MAX_RETRIES, fetch_url


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def test_fetch_url_succeeds_first_try(monkeypatch) -> None:
    seen: list[str] = []

    def fake_urlopen(url: str, timeout: float = 30.0) -> _FakeResponse:
        seen.append(url)
        return _FakeResponse(b"hello")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    result = fetch_url("https://example.com/test")

    assert result == b"hello"
    assert seen == ["https://example.com/test"]


def test_fetch_url_retries_then_succeeds(monkeypatch) -> None:
    call_count = 0

    def fake_urlopen(url: str, timeout: float = 30.0) -> _FakeResponse:
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise urllib.error.URLError("transient failure")
        return _FakeResponse(b"success")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    result = fetch_url("https://example.com/test", base_delay=0.0)

    assert result == b"success"
    assert call_count == 3


def test_fetch_url_raises_after_exhausting_retries(monkeypatch) -> None:
    call_count = 0

    def fake_urlopen(url: str, timeout: float = 30.0) -> _FakeResponse:
        nonlocal call_count
        call_count += 1
        raise OSError("network unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(OSError, match="network unreachable"):
        fetch_url("https://example.com/test", base_delay=0.0)

    assert call_count == DEFAULT_MAX_RETRIES + 1


def test_fetch_url_respects_max_retries(monkeypatch) -> None:
    call_count = 0

    def fake_urlopen(url: str, timeout: float = 30.0) -> _FakeResponse:
        nonlocal call_count
        call_count += 1
        raise urllib.error.URLError("boom")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(urllib.error.URLError):
        fetch_url("https://example.com/test", max_retries=1, base_delay=0.0)

    assert call_count == 2
