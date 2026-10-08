"""Unit tests for upstream discovery source adapters."""

from __future__ import annotations

import urllib.request

from resolver_inventory.settings import SourceEntry
from resolver_inventory.sources.adguard import PROVIDERS_URL as ADGUARD_URL
from resolver_inventory.sources.adguard import AdGuardSource
from resolver_inventory.sources.curl_wiki import PROVIDERS_URL as CURL_URL
from resolver_inventory.sources.curl_wiki import CurlWikiSource
from resolver_inventory.sources.dot import AdGuardDotSource, ManualDotSource
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

    def test_ignores_markdown_table_trailing_tags(self, monkeypatch) -> None:
        body = """
| Provider | Endpoint | Status | Network |
| --- | --- | --- | --- |
| [Marbled Fennec](https://www.marbledfennec.net/public-dns-server/) |
| https://dns.marbledfennec.net/dns-query | :heavy_check_mark: | OpenNIC |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = CurlWikiSource(SourceEntry(type="curl_wiki")).candidates()

        assert len(candidates) == 1
        assert candidates[0].endpoint_url == "https://dns.marbledfennec.net/dns-query"
        assert candidates[0].path == "/dns-query"

    def test_rejects_non_https_and_missing_host_urls(self, monkeypatch) -> None:
        body = """
https:///dns-query
http://example.org/dns-query
https://valid.example/dns-query
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = CurlWikiSource(SourceEntry(type="curl_wiki")).candidates()

        assert [candidate.endpoint_url for candidate in candidates] == [
            "https://valid.example/dns-query"
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


class TestAdGuardDotSource:
    def test_extracts_dot_rows_with_provider_headings(self, monkeypatch) -> None:
        seen: list[str] = []
        body = """
### AdGuard DNS

#### Default

| Protocol       | Address                                     |                |
|----------------|---------------------------------------------|----------------|
| DNS-over-HTTPS | `https://dns.adguard-dns.com/dns-query`     | |
| DNS-over-TLS   | `tls://dns.adguard-dns.com`                 | |
| DNS-over-TLS   | `tls://dns.adguard-dns.com`                 | |

### Other Provider

| DNS-over-TLS | `tls://dot.other.example:8853` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()

        assert seen == [ADGUARD_URL]
        assert [(c.provider, c.host, c.port, c.tls_server_name) for c in candidates] == [
            ("AdGuard DNS", "dns.adguard-dns.com", 853, "dns.adguard-dns.com"),
            ("Other Provider", "dot.other.example", 8853, "dot.other.example"),
        ]
        assert all(c.transport == "dot" for c in candidates)

    def test_fetch_failure_returns_empty(self, monkeypatch) -> None:
        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            raise OSError("Network is unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert candidates == []


class TestManualDotSource:
    def test_parses_endpoints_file(self, tmp_path) -> None:
        toml_file = tmp_path / "manual-dot.toml"
        toml_file.write_text(
            """
[[endpoints]]
host = "dns.example.com"
port = 853
provider = "Example"

[[endpoints]]
host = "192.0.2.1"
provider = "IP endpoint"
tls_server_name = "dns.example.com"
bootstrap_ipv4 = ["192.0.2.1"]
notes = "extra metadata"

[[endpoints]]
host = ""
""",
            encoding="utf-8",
        )
        candidates = ManualDotSource(SourceEntry(type="manual", path=str(toml_file))).candidates()

        assert len(candidates) == 2
        first, second = candidates
        assert (first.host, first.port, first.provider) == (
            "dns.example.com",
            853,
            "Example",
        )
        assert first.tls_server_name == "dns.example.com"
        assert (second.host, second.tls_server_name) == ("192.0.2.1", "dns.example.com")
        assert second.bootstrap_ipv4 == ["192.0.2.1"]
        assert second.metadata == {"notes": "extra metadata"}

    def test_missing_file_returns_empty(self, tmp_path) -> None:
        candidates = ManualDotSource(
            SourceEntry(type="manual", path=str(tmp_path / "absent.toml"))
        ).candidates()
        assert candidates == []

    def test_default_port(self, tmp_path) -> None:
        toml_file = tmp_path / "manual-dot.toml"
        toml_file.write_text('[[endpoints]]\nhost = "dns.example.com"\n', encoding="utf-8")
        candidates = ManualDotSource(SourceEntry(type="manual", path=str(toml_file))).candidates()
        assert candidates[0].port == 853


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

    def test_fetch_failure_returns_empty(self, monkeypatch) -> None:
        calls: list[str] = []

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            calls.append(url)
            raise OSError("Network is unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        source = PublicDnsInfoSource(SourceEntry(type="publicdns_info"))
        candidates = source.candidates()

        assert candidates == []
        assert len(calls) == 4  # 1 initial + 3 retries

    def test_fetch_retries_then_succeeds(self, monkeypatch) -> None:
        body = """ip_address,reliability,as_org,country_id
192.0.2.5,0.99,Works After Retry,US
"""
        call_count = 0

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OSError("Network is unreachable")
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = PublicDnsInfoSource(SourceEntry(type="publicdns_info")).candidates()

        assert call_count == 3
        assert [(candidate.host, candidate.transport) for candidate in candidates] == [
            ("192.0.2.5", "dns-udp"),
            ("192.0.2.5", "dns-tcp"),
        ]
