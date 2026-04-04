"""Unit tests for upstream discovery source adapters."""

from __future__ import annotations

import urllib.request

from resolver_inventory.settings import SourceEntry
from resolver_inventory.sources.adguard import PROVIDERS_URL as ADGUARD_URL
from resolver_inventory.sources.adguard import AdGuardSource
from resolver_inventory.sources.curl_wiki import PROVIDERS_URL as CURL_URL
from resolver_inventory.sources.curl_wiki import CurlWikiSource


class _FakeResponse:
    def __init__(self, body: str) -> None:
        self._body = body.encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class TestCurlWikiSource:
    def test_uses_current_raw_wiki_url_and_extracts_doh_urls(
        self,
        monkeypatch,
    ) -> None:
        seen: list[str] = []
        body = """
| Who runs it | Base URL |
| [Provider A](https://example.com/) |
| https://one.example/dns-query<br>https://two.example/dns-query |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = CurlWikiSource(SourceEntry(type="curl_wiki")).candidates()

        assert seen == [CURL_URL]
        assert [candidate.endpoint_url for candidate in candidates] == [
            "https://one.example/dns-query",
            "https://two.example/dns-query",
        ]


class TestAdGuardSource:
    def test_uses_current_markdown_url_and_extracts_doh_rows(
        self,
        monkeypatch,
    ) -> None:
        seen: list[str] = []
        body = """
### AdGuard DNS

#### Default

| Protocol       | Address                                     |                |
|----------------|---------------------------------------------|----------------|
| DNS-over-HTTPS | `https://dns.adguard-dns.com/dns-query`     | |
| DNS-over-HTTPS | `https://family.adguard-dns.com/dns-query`  | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardSource(SourceEntry(type="adguard")).candidates()

        assert seen == [ADGUARD_URL]
        assert [(candidate.provider, candidate.endpoint_url) for candidate in candidates] == [
            ("AdGuard DNS", "https://dns.adguard-dns.com/dns-query"),
            ("AdGuard DNS", "https://family.adguard-dns.com/dns-query"),
        ]
