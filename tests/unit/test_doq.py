"""Unit tests for the DoQ validator (QUIC path is mocked)."""

from __future__ import annotations

import asyncio
import ssl

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset

from resolver_inventory.models import Candidate
from resolver_inventory.validate.corpus import Corpus, CorpusEntry
from resolver_inventory.validate.doq import (
    _classify_doq_transport_error,
    _probe_nxdomain_doq,
    _probe_positive_doq,
    _query_doq_candidate,
    validate_doq_candidate,
)


def _doq_candidate(
    host: str = "doq.example.com",
    port: int = 853,
    tls_server_name: str | None = None,
    bootstrap_ipv4: list[str] | None = None,
) -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport="doq",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
        bootstrap_ipv4=list(bootstrap_ipv4 or []),
        tls_server_name=tls_server_name,
    )


def _response_for(query: dns.message.Message, answers: list[str]) -> dns.message.Message:
    resp = dns.message.make_response(query)
    if answers:
        qname = query.question[0].name.to_text()
        resp.answer.append(dns.rrset.from_text(qname, 300, "in", "A", *answers))
    return resp


class _FakeQuic:
    """Callable replacement for dns.asyncquery.quic."""

    def __init__(self, answers: list[str] | None = None, exc: Exception | None = None):
        self.answers = answers or []
        self.exc = exc
        self.calls: list[dict] = []

    async def __call__(self, q, where, **kwargs):
        self.calls.append({"where": where, **kwargs})
        if self.exc is not None:
            raise self.exc
        return _response_for(q, self.answers)


def _exact_entry() -> CorpusEntry:
    return CorpusEntry(
        rdtype="A",
        qname="probe.example.com.",
        expected_mode="exact_rrset",
        expected_answers=["192.0.2.1"],
        label="controlled-a",
    )


def _nxdomain_entry() -> CorpusEntry:
    return CorpusEntry(rdtype="A", qname="missing.example.com.", label="nx")


class TestQueryDoqCandidate:
    def test_ip_literal_queries_directly(self, monkeypatch) -> None:
        fake = _FakeQuic(answers=["192.0.2.1"])
        monkeypatch.setattr(dns.asyncquery, "quic", fake)
        candidate = _doq_candidate(host="94.140.14.14", tls_server_name="dns.adguard-dns.com")

        resp, _ = asyncio.run(
            _query_doq_candidate(candidate, dns.message.make_query("x.example.", "A"), 2.0, None)
        )
        assert resp is not None
        assert fake.calls[0]["where"] == "94.140.14.14"
        assert fake.calls[0]["server_hostname"] == "dns.adguard-dns.com"
        assert fake.calls[0]["port"] == 853

    def test_bootstrap_addresses_used_without_resolution(self, monkeypatch) -> None:
        fake = _FakeQuic(answers=["192.0.2.1"])
        monkeypatch.setattr(dns.asyncquery, "quic", fake)
        candidate = _doq_candidate(
            host="doq.example.com", bootstrap_ipv4=["192.0.2.55", "192.0.2.56"]
        )

        asyncio.run(
            _query_doq_candidate(candidate, dns.message.make_query("x.example.", "A"), 2.0, None)
        )
        assert fake.calls[0]["where"] == "192.0.2.55"
        assert fake.calls[0]["server_hostname"] == "doq.example.com"

    def test_unresolvable_hostname_raises(self, monkeypatch) -> None:
        async def _no_resolve(*args, **kwargs):
            raise dns.resolver.NXDOMAIN()

        monkeypatch.setattr(
            dns.asyncresolver.Resolver, "resolve", lambda self, *a, **k: _no_resolve()
        )
        candidate = _doq_candidate(host="nonexistent.invalid")
        try:
            asyncio.run(
                _query_doq_candidate(
                    candidate, dns.message.make_query("x.example.", "A"), 0.5, None
                )
            )
        except dns.exception.DNSException as exc:
            assert "cannot resolve DoQ host" in str(exc)
        else:
            raise AssertionError("expected DNSException")


class TestClassifyDoqTransportError:
    def test_ssl_cert_verification_maps_tls(self) -> None:
        exc = ssl.SSLCertVerificationError("certificate verify failed")
        assert _classify_doq_transport_error(exc).startswith("tls_error")

    def test_hostname_mismatch_maps_tls_name_mismatch(self) -> None:
        exc = ssl.SSLCertVerificationError("hostname 'x' doesn't match 'y'")
        assert _classify_doq_transport_error(exc).startswith("tls_name_mismatch")

    def test_aioquic_crypto_error_maps_tls(self) -> None:
        class CryptoError(Exception):
            pass

        CryptoError.__module__ = "aioquic.tls"
        assert _classify_doq_transport_error(CryptoError("bad certificate")).startswith("tls_error")

    def test_aioquic_transport_error_maps_timeout(self) -> None:
        class ConnectionError_(Exception):
            pass

        ConnectionError_.__module__ = "aioquic.quic.connection"
        assert _classify_doq_transport_error(ConnectionError_("connection lost")).startswith(
            "timeout_or_error"
        )

    def test_generic_error_maps_timeout(self) -> None:
        assert _classify_doq_transport_error(TimeoutError("t")).startswith("timeout_or_error")


class TestDoqProbes:
    def test_positive_probe_success(self, monkeypatch) -> None:
        fake = _FakeQuic(answers=["192.0.2.1"])
        monkeypatch.setattr(dns.asyncquery, "quic", fake)
        result = asyncio.run(
            _probe_positive_doq(
                _exact_entry(),
                _doq_candidate(host="94.140.14.14"),
                2.0,
                ["1.1.1.1"],
                {},
            )
        )
        assert result.ok
        assert result.probe == "doq:positive:controlled-a"
        assert result.latency_ms is not None

    def test_positive_probe_transport_error(self, monkeypatch) -> None:
        fake = _FakeQuic(exc=TimeoutError("no route"))
        monkeypatch.setattr(dns.asyncquery, "quic", fake)
        result = asyncio.run(
            _probe_positive_doq(
                _exact_entry(),
                _doq_candidate(host="94.140.14.14"),
                2.0,
                ["1.1.1.1"],
                {},
            )
        )
        assert not result.ok
        assert result.error is not None
        assert result.error.startswith("timeout_or_error")

    def test_nxdomain_probe_success(self, monkeypatch) -> None:
        class _NXFake(_FakeQuic):
            async def __call__(self, q, where, **kwargs):
                resp = _response_for(q, [])
                resp.set_rcode(dns.rcode.NXDOMAIN)
                return resp

        monkeypatch.setattr(dns.asyncquery, "quic", _NXFake())
        result = asyncio.run(
            _probe_nxdomain_doq(_nxdomain_entry(), _doq_candidate(host="94.140.14.14"), 2.0)
        )
        assert result.ok
        assert result.probe == "doq:nxdomain:nx"

    def test_nxdomain_probe_spoofed(self, monkeypatch) -> None:
        fake = _FakeQuic(answers=["192.0.2.1"])  # NOERROR + answers for NX name
        monkeypatch.setattr(dns.asyncquery, "quic", fake)
        result = asyncio.run(
            _probe_nxdomain_doq(_nxdomain_entry(), _doq_candidate(host="94.140.14.14"), 2.0)
        )
        assert not result.ok
        assert result.error == "nxdomain_spoofing"

    def test_validate_doq_candidate_runs_all_probes(self, monkeypatch) -> None:
        class _NXFake(_FakeQuic):
            async def __call__(self, q, where, **kwargs):
                qname = q.question[0].name.to_text()
                if qname.startswith("missing."):
                    resp = _response_for(q, [])
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp
                return _response_for(q, ["192.0.2.1"])

        monkeypatch.setattr(dns.asyncquery, "quic", _NXFake())
        corpus = Corpus(positive=[_exact_entry()], nxdomain=[_nxdomain_entry()])
        results = asyncio.run(
            validate_doq_candidate(_doq_candidate(host="94.140.14.14"), corpus, rounds=2)
        )
        names = sorted(r.probe for r in results)
        assert names == [
            "doq:nxdomain:nx",
            "doq:nxdomain:nx",
            "doq:positive:controlled-a",
            "doq:positive:controlled-a",
        ]
        assert all(r.ok for r in results)
