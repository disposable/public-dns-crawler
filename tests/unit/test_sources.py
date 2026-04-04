"""Unit tests for upstream discovery source adapters."""

from __future__ import annotations

import urllib.request

from resolver_inventory.settings import SourceEntry
from resolver_inventory.sources.adguard import PROVIDERS_URL as ADGUARD_URL
from resolver_inventory.sources.adguard import AdGuardSource
from resolver_inventory.sources.curl_wiki import PROVIDERS_URL as CURL_URL
from resolver_inventory.sources.curl_wiki import CurlWikiSource
from resolver_inventory.sources.publicdns_info import (
    DEFAULT_URL as PUBLICDNS_INFO_URL,
)
from resolver_inventory.sources.publicdns_info import PublicDnsInfoSource


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


class TestPublicDnsInfoSource:
    def test_filters_out_low_reliability_hosts(self, monkeypatch) -> None:
        seen: list[str] = []
        body = """ip_address,reliability,as_org,country_id
192.0.2.1,0.49,Too Flaky,US
192.0.2.2,0.50,Stable Enough,DE
192.0.2.3,0.95,Very Stable,CH
192.0.2.4,,Missing Reliability,FR
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        source = PublicDnsInfoSource(
            SourceEntry(type="publicdns_info", extra={"min_reliability": 0.50})
        )
        candidates = source.candidates()

        assert seen == [PUBLICDNS_INFO_URL]
        assert [(candidate.host, candidate.transport) for candidate in candidates] == [
            ("192.0.2.2", "dns-udp"),
            ("192.0.2.2", "dns-tcp"),
            ("192.0.2.3", "dns-udp"),
            ("192.0.2.3", "dns-tcp"),
        ]
        assert [record.reason for record in source.filtered_candidates()] == [
            "source_reliability_below_min",
            "source_reliability_below_min",
            "source_reliability_below_min",
            "source_reliability_below_min",
        ]

    def test_allows_custom_min_reliability(self, monkeypatch) -> None:
        body = """ip_address,reliability,as_org,country_id
192.0.2.10,0.39,Barely There,US
192.0.2.11,0.41,Included,US
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = PublicDnsInfoSource(
            SourceEntry(type="publicdns_info", extra={"min_reliability": 0.40})
        ).candidates()

        assert [(candidate.host, candidate.transport) for candidate in candidates] == [
            ("192.0.2.11", "dns-udp"),
            ("192.0.2.11", "dns-tcp"),
        ]

    def test_fetch_failure_is_fatal(self, monkeypatch) -> None:
        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            raise OSError("Network is unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        source = PublicDnsInfoSource(SourceEntry(type="publicdns_info"))
        import pytest

        with pytest.raises(RuntimeError, match="publicdns_info fetch failed"):
            source.candidates()
