"""Unit tests for normalization."""

from __future__ import annotations

from resolver_inventory.models import Candidate, FilteredCandidate
from resolver_inventory.normalize.dns import normalize_dns_candidates
from resolver_inventory.normalize.doh import normalize_doh_candidates
from resolver_inventory.normalize.dot import normalize_dot_candidates


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
        assert result[0].endpoint_url == "https://dns.example.com/dns-query"

    def test_path_case_and_query_are_preserved(self) -> None:
        c = _doh("https://DNS.Example.COM/DNS-Query?name=Example.COM&cd=0")
        result = normalize_doh_candidates([c])
        assert len(result) == 1
        assert result[0].endpoint_url == "https://dns.example.com/DNS-Query?name=Example.COM&cd=0"

    def test_distinct_doh_paths_are_not_merged(self) -> None:
        result = normalize_doh_candidates(
            [
                _doh("https://dns.example.com/dns-query"),
                _doh("https://dns.example.com/DNS-Query"),
            ]
        )
        assert len(result) == 2

    def test_default_port_is_normalized(self) -> None:
        result = normalize_doh_candidates(
            [
                _doh("https://dns.example.com:443/dns-query"),
                _doh("https://dns.example.com/dns-query"),
            ]
        )
        assert len(result) == 1

    def test_tls_server_name_preserved(self) -> None:
        result = normalize_doh_candidates([_doh("https://dns.example.com/dns-query")])
        assert result[0].tls_server_name == "dns.example.com"


def _dot(
    host: str,
    port: int = 853,
    tls_server_name: str | None = None,
) -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport="dot",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
        tls_server_name=tls_server_name,
    )


class TestNormalizeDot:
    def test_hostname_endpoint(self) -> None:
        result = normalize_dot_candidates([_dot("dns.example.com")])
        assert len(result) == 1
        assert result[0].host == "dns.example.com"
        assert result[0].port == 853
        assert result[0].tls_server_name == "dns.example.com"

    def test_ip_endpoint_has_no_tls_name_by_default(self) -> None:
        result = normalize_dot_candidates([_dot("192.0.2.1")])
        assert len(result) == 1
        assert result[0].host == "192.0.2.1"
        assert result[0].tls_server_name is None

    def test_ip_endpoint_with_explicit_tls_name(self) -> None:
        result = normalize_dot_candidates([_dot("1.1.1.1", tls_server_name="one.one.one.one")])
        assert len(result) == 1
        assert result[0].tls_server_name == "one.one.one.one"

    def test_invalid_host_dropped(self) -> None:
        filtered: list[FilteredCandidate] = []
        result = normalize_dot_candidates([_dot("not a host!!")], filtered=filtered)
        assert result == []
        assert len(filtered) == 1
        assert filtered[0].reason == "invalid_dot_endpoint"

    def test_invalid_port_dropped(self) -> None:
        filtered: list[FilteredCandidate] = []
        result = normalize_dot_candidates([_dot("dns.example.com", port=70000)], filtered=filtered)
        assert result == []
        assert filtered[0].reason == "invalid_dot_endpoint"

    def test_deduplication(self) -> None:
        filtered: list[FilteredCandidate] = []
        candidates = [_dot("dns.example.com"), _dot("DNS.EXAMPLE.COM.")]
        result = normalize_dot_candidates(candidates, filtered=filtered)
        assert len(result) == 1
        assert filtered[0].reason == "duplicate_dot_candidate"

    def test_distinct_tls_names_not_merged(self) -> None:
        result = normalize_dot_candidates(
            [
                _dot("192.0.2.1", tls_server_name="a.example.com"),
                _dot("192.0.2.1", tls_server_name="b.example.com"),
            ]
        )
        assert len(result) == 2

    def test_non_dot_candidates_skipped(self) -> None:
        result = normalize_dot_candidates([_dns("1.1.1.1")])
        assert result == []

    def test_host_lowercased(self) -> None:
        result = normalize_dot_candidates([_dot("DNS.Example.COM")])
        assert result[0].host == "dns.example.com"
        assert result[0].tls_server_name == "dns.example.com"

    def test_bootstrap_addresses_preserved(self) -> None:
        c = _dot("dns.example.com")
        c.bootstrap_ipv4 = ["192.0.2.1"]
        c.bootstrap_ipv6 = ["2001:db8::1"]
        result = normalize_dot_candidates([c])
        assert result[0].bootstrap_ipv4 == ["192.0.2.1"]
        assert result[0].bootstrap_ipv6 == ["2001:db8::1"]

    def test_explicit_tls_name_equal_to_host_dedupes_with_implicit(self) -> None:
        """A redundant explicit name must not produce a second endpoint -
        both forms collapse to the same resolver key."""
        filtered: list[FilteredCandidate] = []
        result = normalize_dot_candidates(
            [_dot("192.0.2.1"), _dot("192.0.2.1", tls_server_name="192.0.2.1")],
            filtered=filtered,
        )
        assert len(result) == 1
        assert filtered[0].reason == "duplicate_dot_candidate"

    def test_invalid_bootstrap_ipv4_dropped(self) -> None:
        filtered: list[FilteredCandidate] = []
        c = _dot("dns.example.com")
        c.bootstrap_ipv4 = ["not-an-ip"]
        result = normalize_dot_candidates([c], filtered=filtered)
        assert result == []
        assert filtered[0].reason == "invalid_dot_endpoint"

    def test_wrong_family_bootstrap_dropped(self) -> None:
        filtered: list[FilteredCandidate] = []
        c = _dot("dns.example.com")
        c.bootstrap_ipv4 = ["2001:db8::1"]
        result = normalize_dot_candidates([c], filtered=filtered)
        assert result == []
        assert filtered[0].reason == "invalid_dot_endpoint"

    def test_invalid_tls_server_name_dropped(self) -> None:
        filtered: list[FilteredCandidate] = []
        result = normalize_dot_candidates(
            [_dot("192.0.2.1", tls_server_name="not a host!")],
            filtered=filtered,
        )
        assert result == []
        assert filtered[0].reason == "invalid_dot_endpoint"

    def test_tls_server_name_normalized(self) -> None:
        result = normalize_dot_candidates([_dot("192.0.2.1", tls_server_name="DNS.Example.COM.")])
        assert result[0].tls_server_name == "dns.example.com"
