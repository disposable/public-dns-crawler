"""Unit tests for upstream discovery source adapters."""

from __future__ import annotations

import urllib.request

from resolver_inventory.settings import SourceEntry
from resolver_inventory.sources.adguard import PROVIDERS_URL as ADGUARD_URL
from resolver_inventory.sources.adguard import AdGuardDnsSource, AdGuardSource
from resolver_inventory.sources.curl_wiki import PROVIDERS_URL as CURL_URL
from resolver_inventory.sources.curl_wiki import CurlWikiSource
from resolver_inventory.sources.dnscrypt import (
    DNSCRYPT_RESOLVERS_URL,
    DnsCryptDnsSource,
    DnsCryptDohSource,
    DnsCryptDoqSource,
    DnsCryptDotSource,
)
from resolver_inventory.sources.doq import AdGuardDoqSource, ManualDoqSource
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

    def test_fragment_carries_tls_auth_name(self, monkeypatch) -> None:
        """tls://ip#name endpoints keep the fragment as tls_server_name."""
        body = """
### Provider

| DNS-over-TLS | `tls://9.9.9.9#dns.quad9.net` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert len(candidates) == 1
        assert candidates[0].host == "9.9.9.9"
        assert candidates[0].port == 853
        assert candidates[0].tls_server_name == "dns.quad9.net"

    def test_malformed_urls_are_skipped(self, monkeypatch) -> None:
        """Unbalanced IPv6 brackets and invalid ports must not crash parsing."""
        body = """
### Provider

| DNS-over-TLS | `tls://[::1` | |
| DNS-over-TLS | `tls://dns.example.com:99999` | |
| DNS-over-TLS | `tls://dns.example.com:abc` | |
| DNS-over-TLS | `tls://good.example.com` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert [c.host for c in candidates] == ["good.example.com"]

    def test_prefixed_rows_with_bootstrap_addresses(self, monkeypatch) -> None:
        """Hostname:/IP:/IPv6: prefixed cells yield endpoints plus bootstrap IPs."""
        rows = [
            "### DNS Privacy",
            "",
            "| Protocol | Address | |",
            "|---|---|---|",
            "| DNS-over-TLS | Hostname: `tls://getdnsapi.net`"
            " IP: `185.49.141.37` and IPv6: `2a04:b900:0:100::37` | |",
            "| DNS-over-TLS | Provider: `Surfnet`"
            " Hostname: `tls://dnsovertls.sinodun.com` IP: `145.100.185.15`"
            " and IPv6: `2001:610:1:40ba:145:100:185:15` | |",
            "| DNS-over-TLS | `tls://plain.example.com` | |",
        ]
        body = "\n".join(rows)

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert [c.host for c in candidates] == [
            "getdnsapi.net",
            "dnsovertls.sinodun.com",
            "plain.example.com",
        ]
        assert candidates[0].bootstrap_ipv4 == ["185.49.141.37"]
        assert candidates[0].bootstrap_ipv6 == ["2a04:b900:0:100::37"]
        assert candidates[1].bootstrap_ipv4 == ["145.100.185.15"]
        assert candidates[1].tls_server_name == "dnsovertls.sinodun.com"
        assert candidates[1].provider == "DNS Privacy"
        assert candidates[2].bootstrap_ipv4 == []

    def test_label_variants_and_bare_hostname_rows(self, monkeypatch) -> None:
        """Variant labels (IPv4 suffix, - Private) and Hostname-only rows."""
        body = """
### CIRA

| Protocol | Address | |
|---|---|---|
| DNS-over-TLS - Private | Hostname: `tls://private.example.ca` IP: `149.112.121.10` | |
| DNS-over-TLS, IPv4 | `tls://149.112.121.20` | |
| DNS-over-TLS | Hostname: `dnsotls.lab.example` IP: `200.1.123.46` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert [(c.host, c.tls_server_name) for c in candidates] == [
            ("private.example.ca", "private.example.ca"),
            ("149.112.121.20", "149.112.121.20"),
            ("dnsotls.lab.example", "dnsotls.lab.example"),
        ]
        assert candidates[0].bootstrap_ipv4 == ["149.112.121.10"]
        assert candidates[2].bootstrap_ipv4 == ["200.1.123.46"]

    def test_address_cell_only_not_link_cell(self, monkeypatch) -> None:
        """tls:// references in the link cell must not create endpoints."""
        body = """
### Provider

| DNS-over-TLS | `tls://real.example.com` | [Add](https://x.example/?a=tls://decoy.example.com) |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDotSource(SourceEntry(type="adguard")).candidates()
        assert [c.host for c in candidates] == ["real.example.com"]


class TestAdGuardDnsSource:
    def test_extracts_ipv4_and_ipv6_rows(self, monkeypatch) -> None:
        seen: list[str] = []
        body = """
### AdGuard DNS

| Protocol | Address | |
|---|---|---|
| DNS, IPv4 | `94.140.14.14` and `94.140.15.15` | |
| DNS, IPv6 | `2a10:50c0::ad1:ff` and `2a10:50c0::ad2:ff` | |
| DNS-over-HTTPS | `https://dns.adguard-dns.com/dns-query` | |

### Other

| DNS, IPv4 | `1.2.3.4` | |
| DNS, IPv4 | `94.140.14.14` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDnsSource(SourceEntry(type="adguard")).candidates()
        assert seen == [ADGUARD_URL]
        hosts = sorted({c.host for c in candidates})
        assert hosts == [
            "1.2.3.4",
            "2a10:50c0::ad1:ff",
            "2a10:50c0::ad2:ff",
            "94.140.14.14",
            "94.140.15.15",
        ]
        per_host = {}
        for c in candidates:
            per_host.setdefault(c.host, set()).add(c.transport)
        assert per_host["94.140.14.14"] == {"dns-udp", "dns-tcp"}
        assert all(c.port == 53 for c in candidates)
        assert candidates[0].provider == "AdGuard DNS"

    def test_skips_non_ip_tokens(self, monkeypatch) -> None:
        body = """
### Provider

| DNS, IPv4 | `not-an-ip` and `192.0.2.1` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDnsSource(SourceEntry(type="adguard")).candidates()
        assert {c.host for c in candidates} == {"192.0.2.1"}


class TestAdGuardDoqSource:
    def test_extracts_quic_rows(self, monkeypatch) -> None:
        body = """
### AdGuard DNS

| Protocol | Address | |
|---|---|---|
| DNS-over-QUIC | `quic://dns.adguard-dns.com` | |
| DNS-over-QUIC | `quic://dns.adguard-dns.com` | |
| DNS-over-QUIC | Hostname: `quic://dns.other.example` IP: `1.2.3.4` | |
| DNS-over-QUIC, IPv4 | `quic://94.140.14.14` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDoqSource(SourceEntry(type="adguard")).candidates()
        assert [(c.host, c.port, c.transport) for c in candidates] == [
            ("dns.adguard-dns.com", 853, "doq"),
            ("dns.other.example", 853, "doq"),
            ("94.140.14.14", 853, "doq"),
        ]
        assert candidates[1].bootstrap_ipv4 == ["1.2.3.4"]

    def test_bare_hostname_row(self, monkeypatch) -> None:
        body = """
### Provider

| DNS-over-QUIC | Hostname: `doq.example.com` | |
"""

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

        candidates = AdGuardDoqSource(SourceEntry(type="adguard")).candidates()
        assert [c.host for c in candidates] == ["doq.example.com"]


class TestManualDoqSource:
    def test_parses_endpoints_file(self, tmp_path) -> None:
        toml_file = tmp_path / "manual-doq.toml"
        toml_file.write_text(
            """
[[endpoints]]
host = "dns.example.com"
provider = "Example"

[[endpoints]]
host = "192.0.2.1"
tls_server_name = "dns.example.com"
""",
            encoding="utf-8",
        )
        candidates = ManualDoqSource(SourceEntry(type="manual", path=str(toml_file))).candidates()
        assert len(candidates) == 2
        assert all(c.transport == "doq" for c in candidates)
        assert candidates[0].port == 853
        assert candidates[1].tls_server_name == "dns.example.com"


def _lp(data: bytes) -> bytes:
    return bytes([len(data)]) + data


def _vlp(items: list[bytes]) -> bytes:
    out = b""
    for i, item in enumerate(items):
        flag = 0x80 if i < len(items) - 1 else 0
        out += bytes([flag | len(item)]) + item
    if not items:
        out = b"\x00"
    return out


def _doh_stamp(
    addr: bytes,
    hostname: bytes,
    path: bytes = b"/dns-query",
    hashes: list[bytes] | None = None,
    bootstrap: list[bytes] | None = None,
) -> str:
    import base64

    raw = b"\x02" + b"\x00" * 8 + _lp(addr) + _vlp(hashes or []) + _lp(hostname) + _lp(path)
    if bootstrap:
        raw += _vlp(bootstrap)
    return "sdns://" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _dot_stamp(addr: bytes, hostname: bytes) -> str:
    import base64

    raw = b"\x03" + b"\x00" * 8 + _lp(addr) + _vlp([]) + _lp(hostname)
    return "sdns://" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _doq_stamp(addr: bytes, hostname: bytes) -> str:
    import base64

    raw = b"\x04" + b"\x00" * 8 + _lp(addr) + _vlp([]) + _lp(hostname)
    return "sdns://" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _plain_stamp(addr: bytes) -> str:
    import base64

    raw = b"\x00" + b"\x00" * 8 + _lp(addr)
    return "sdns://" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _dnscrypt_stamp(addr: bytes) -> str:
    import base64

    raw = b"\x01" + b"\x00" * 8 + _lp(addr) + _lp(b"x" * 32) + _lp(b"provider.name")
    return "sdns://" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class TestDnsCryptSources:
    def _patch_fetch(self, monkeypatch, body: str) -> list[str]:
        seen: list[str] = []

        def fake_urlopen(url: str, timeout: int = 30) -> _FakeResponse:
            seen.append(url)
            return _FakeResponse(body)

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        return seen

    def test_doh_stamps_decode_to_candidates(self, monkeypatch) -> None:
        body = f"""
## aa.net.uk-dns1

Description here.

{_doh_stamp(b"217.169.20.22", b"dns.aa.net.uk")}

## adfilter-syd

{_doh_stamp(b"112.213.32.219", b"syd.adfilter.net", path=b"/dns-query")}
"""
        seen = self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDohSource(SourceEntry(type="dnscrypt")).candidates()
        assert seen == [DNSCRYPT_RESOLVERS_URL]
        assert [(c.provider, c.host, c.port, c.endpoint_url) for c in candidates] == [
            (
                "aa.net.uk-dns1",
                "dns.aa.net.uk",
                443,
                "https://dns.aa.net.uk:443/dns-query",
            ),
            (
                "adfilter-syd",
                "syd.adfilter.net",
                443,
                "https://syd.adfilter.net:443/dns-query",
            ),
        ]
        assert candidates[0].bootstrap_ipv4 == ["217.169.20.22"]

    def test_doh_stamp_with_multi_hash_vlp(self, monkeypatch) -> None:
        """Multiple cert hashes use the 0x80 continuation bit on length bytes."""
        stamp = _doh_stamp(
            b"149.112.121.20",
            b"protected.canadianshield.cira.ca",  # 32 chars - VLP edge case
            hashes=[b"h" * 32, b"i" * 32],
            bootstrap=[b"1.1.1.1"],
        )
        body = f"## cira\n\n{stamp}\n"
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDohSource(SourceEntry(type="dnscrypt")).candidates()
        assert len(candidates) == 1
        c = candidates[0]
        assert c.host == "protected.canadianshield.cira.ca"
        assert c.endpoint_url == ("https://protected.canadianshield.cira.ca:443/dns-query")
        # Bootstrap resolvers in the stamp are not server addresses.
        assert c.bootstrap_ipv4 == ["149.112.121.20"]

    def test_doh_hostname_port(self, monkeypatch) -> None:
        stamp = _doh_stamp(b"", b"dns.example.com:8443")
        self._patch_fetch(monkeypatch, f"## p\n\n{stamp}\n")
        candidates = DnsCryptDohSource(SourceEntry(type="dnscrypt")).candidates()
        assert len(candidates) == 1
        assert candidates[0].port == 8443
        assert candidates[0].endpoint_url == "https://dns.example.com:8443/dns-query"

    def test_non_doh_stamps_and_malformed_skipped(self, monkeypatch) -> None:
        body = "\n".join(
            [
                "## p",
                _dnscrypt_stamp(b"1.2.3.4"),  # proto 0x01 - unsupported
                "sdns://!!!invalid-base64!!!",
                "sdns://AA",  # too short
                _doh_stamp(b"1.2.3.4", b"ok.example.com"),
            ]
        )
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDohSource(SourceEntry(type="dnscrypt")).candidates()
        assert [c.host for c in candidates] == ["ok.example.com"]

    def test_dot_family_emits_dot_candidates(self, monkeypatch) -> None:
        body = (
            "## p\n\n"
            + _dot_stamp(b"9.9.9.9", b"dns.quad9.net")
            + "\n"
            + _doh_stamp(b"1.1.1.1", b"doh.example.com")
            + "\n"
        )
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDotSource(SourceEntry(type="dnscrypt")).candidates()
        assert [(c.host, c.transport, c.tls_server_name) for c in candidates] == [
            ("dns.quad9.net", "dot", "dns.quad9.net")
        ]
        assert candidates[0].bootstrap_ipv4 == ["9.9.9.9"]

    def test_doq_family_emits_doq_candidates(self, monkeypatch) -> None:
        body = f"## p\n\n{_doq_stamp(b'9.9.9.9', b'dns.quad9.net')}\n"
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDoqSource(SourceEntry(type="dnscrypt")).candidates()
        assert [(c.host, c.transport, c.port) for c in candidates] == [
            ("dns.quad9.net", "doq", 443)
        ]

    def test_plain_family_emits_udp_and_tcp(self, monkeypatch) -> None:
        body = f"## p\n\n{_plain_stamp(b'192.0.2.53')}\n"
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDnsSource(SourceEntry(type="dnscrypt")).candidates()
        assert sorted((c.host, c.transport) for c in candidates) == [
            ("192.0.2.53", "dns-tcp"),
            ("192.0.2.53", "dns-udp"),
        ]

    def test_dedupes_identical_stamps(self, monkeypatch) -> None:
        stamp = _doh_stamp(b"1.2.3.4", b"dup.example.com")
        body = f"## a\n\n{stamp}\n\n## b\n\n{stamp}\n"
        self._patch_fetch(monkeypatch, body)
        candidates = DnsCryptDohSource(SourceEntry(type="dnscrypt")).candidates()
        assert len(candidates) == 1


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
