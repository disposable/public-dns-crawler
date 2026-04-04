"""Unit tests for normalization."""

from __future__ import annotations

from resolver_inventory.models import Candidate, FilteredCandidate
from resolver_inventory.normalize.dns import normalize_dns_candidates
from resolver_inventory.normalize.doh import normalize_doh_candidates


def _dns(host: str, transport: str = "dns-udp") -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport=transport,  # type: ignore[arg-type]
        endpoint_url=None,
        host=host,
        port=53,
        path=None,
    )


def _doh(url: str) -> Candidate:
    from urllib.parse import urlparse

    p = urlparse(url)
    return Candidate(
        provider=None,
        source="test",
        transport="doh",
        endpoint_url=url,
        host=p.hostname or "",
        port=p.port or 443,
        path=p.path or "/dns-query",
        tls_server_name=p.hostname or "",
    )


class TestNormalizeDns:
    def test_valid_ipv4(self) -> None:
        result = normalize_dns_candidates([_dns("192.0.2.1")])
        assert len(result) == 1
        assert result[0].host == "192.0.2.1"

    def test_valid_ipv6(self) -> None:
        result = normalize_dns_candidates([_dns("2001:db8::1")])
        assert len(result) == 1
        assert result[0].host == "2001:db8::1"

    def test_invalid_host_dropped(self) -> None:
        result = normalize_dns_candidates([_dns("not-an-ip")])
        assert result == []

    def test_invalid_host_recorded_in_filtered_list(self) -> None:
        filtered: list[FilteredCandidate] = []
        result = normalize_dns_candidates([_dns("not-an-ip")], filtered=filtered)
        assert result == []
        assert len(filtered) == 1
        assert filtered[0].reason == "invalid_dns_host"

    def test_deduplication(self) -> None:
        candidates = [_dns("1.1.1.1"), _dns("1.1.1.1")]
        result = normalize_dns_candidates(candidates)
        assert len(result) == 1

    def test_duplicate_recorded_in_filtered_list(self) -> None:
        filtered: list[FilteredCandidate] = []
        candidates = [_dns("1.1.1.1"), _dns("1.1.1.1")]
        result = normalize_dns_candidates(candidates, filtered=filtered)
        assert len(result) == 1
        assert len(filtered) == 1
        assert filtered[0].reason == "duplicate_dns_candidate"

    def test_udp_and_tcp_kept_separately(self) -> None:
        candidates = [_dns("1.1.1.1", "dns-udp"), _dns("1.1.1.1", "dns-tcp")]
        result = normalize_dns_candidates(candidates)
        assert len(result) == 2

    def test_doh_candidates_skipped(self) -> None:
        candidates = [_doh("https://dns.example.com/dns-query")]
        result = normalize_dns_candidates(candidates)
        assert result == []

    def test_ipv4_normalization(self) -> None:
        result = normalize_dns_candidates([_dns("  192.0.2.1  ")])
        assert len(result) == 1
        assert result[0].host == "192.0.2.1"


class TestNormalizeDoh:
    def test_valid_url(self) -> None:
        result = normalize_doh_candidates([_doh("https://dns.example.com/dns-query")])
        assert len(result) == 1
        assert result[0].host == "dns.example.com"

    def test_http_url_dropped(self) -> None:
        c = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="http://dns.example.com/dns-query",
            host="dns.example.com",
            port=80,
            path="/dns-query",
        )
        result = normalize_doh_candidates([c])
        assert result == []

    def test_invalid_doh_recorded_in_filtered_list(self) -> None:
        filtered: list[FilteredCandidate] = []
        c = Candidate(
            provider=None,
            source="test",
            transport="doh",
            endpoint_url="http://dns.example.com/dns-query",
            host="dns.example.com",
            port=80,
            path="/dns-query",
        )
        result = normalize_doh_candidates([c], filtered=filtered)
        assert result == []
        assert len(filtered) == 1
        assert filtered[0].reason == "invalid_doh_url"

    def test_deduplication(self) -> None:
        candidates = [
            _doh("https://dns.example.com/dns-query"),
            _doh("https://dns.example.com/dns-query"),
        ]
        result = normalize_doh_candidates(candidates)
        assert len(result) == 1

    def test_duplicate_doh_recorded_in_filtered_list(self) -> None:
        filtered: list[FilteredCandidate] = []
        candidates = [
            _doh("https://dns.example.com/dns-query"),
            _doh("https://dns.example.com/dns-query"),
        ]
        result = normalize_doh_candidates(candidates, filtered=filtered)
        assert len(result) == 1
        assert len(filtered) == 1
        assert filtered[0].reason == "duplicate_doh_candidate"

    def test_dns_candidates_skipped(self) -> None:
        result = normalize_doh_candidates([_dns("1.1.1.1")])
        assert result == []

    def test_host_lowercased(self) -> None:
        c = _doh("https://DNS.Example.COM/dns-query")
        result = normalize_doh_candidates([c])
        assert len(result) == 1
        assert result[0].host == "dns.example.com"

    def test_tls_server_name_preserved(self) -> None:
        result = normalize_doh_candidates([_doh("https://dns.example.com/dns-query")])
        assert result[0].tls_server_name == "dns.example.com"
