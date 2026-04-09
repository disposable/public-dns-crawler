"""Parity regression checks between python and massdns plain DNS backends."""

from __future__ import annotations

from pathlib import Path

import dns.message
import dns.rrset
import pytest

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate import validate_candidates


def _candidate() -> Candidate:
    return Candidate(
        provider=None,
        source="test",
        transport="dns-udp",
        endpoint_url=None,
        host="127.0.0.1",
        port=53,
        path=None,
    )


def _settings() -> Settings:
    settings = Settings()
    settings.validation.rounds = 1
    settings.validation.timeout_ms = 1000
    settings.validation.corpus.mode = "controlled"
    settings.validation.corpus.zone = "test.local"
    return settings


def _make_fake_massdns(tmp_path: Path) -> Path:
    script = tmp_path / "fake_massdns_parity.py"
    script.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import json, sys",
                "for line in sys.stdin:",
                "    parts = line.strip().split()",
                "    if len(parts) < 3:",
                "        continue",
                "    qname, rdtype, resolver = parts[0], parts[1], parts[2]",
                "    if qname.startswith('nxtest-sentinel-xyzzy.'):",  # controlled NX probe
                "        payload = {",
                "            'name': qname, 'resolver': resolver, 'type': rdtype,",
                "            'status': 'NXDOMAIN', 'answers': [], 'latency_ms': 1.0",
                "        }",
                "    elif rdtype == 'A':",
                "        payload = {",
                "            'name': qname, 'resolver': resolver, 'type': rdtype,",
                "            'status': 'NOERROR',",
                "            'answers': [{'type': 'A', 'data': '192.0.2.1'}],",
                "            'latency_ms': 1.0",
                "        }",
                "    elif rdtype == 'AAAA':",
                "        payload = {",
                "            'name': qname, 'resolver': resolver, 'type': rdtype,",
                "            'status': 'NOERROR',",
                "            'answers': [{'type': 'AAAA', 'data': '2001:db8::1'}],",
                "            'latency_ms': 1.0",
                "        }",
                "    elif rdtype == 'TXT':",
                "        payload = {",
                "            'name': qname, 'resolver': resolver, 'type': rdtype,",
                "            'status': 'NOERROR',",
                "            'answers': [{'type': 'TXT', 'data': '\"v=test1\"'}],",
                "            'latency_ms': 1.0",
                "        }",
                "    else:",
                "        payload = {",
                "            'name': qname, 'resolver': resolver, 'type': rdtype,",
                "            'status': 'NOERROR',",
                "            'answers': [{'type': 'CNAME', 'data': 'a.ok.test.local.'}],",
                "            'latency_ms': 1.0",
                "        }",
                "    sys.stdout.write(json.dumps(payload) + '\\n')",
                "    sys.stdout.flush()",
            ]
        ),
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script


def _fake_dns_response(msg: dns.message.Message) -> dns.message.Message:
    query_name = msg.question[0].name.to_text()
    query_type = dns.rdatatype.to_text(msg.question[0].rdtype)
    response = dns.message.make_response(msg)
    if query_name.startswith("nxtest-sentinel-xyzzy."):
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response
    if query_type == "A":
        response.answer.append(dns.rrset.from_text(query_name, 60, "IN", "A", "192.0.2.1"))
    elif query_type == "AAAA":
        response.answer.append(dns.rrset.from_text(query_name, 60, "IN", "AAAA", "2001:db8::1"))
    elif query_type == "TXT":
        response.answer.append(dns.rrset.from_text(query_name, 60, "IN", "TXT", '"v=test1"'))
    elif query_type == "CNAME":
        response.answer.append(
            dns.rrset.from_text(query_name, 60, "IN", "CNAME", "a.ok.test.local.")
        )
    return response


def test_massdns_backend_decision_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_query_udp(
        host: str,
        port: int,
        msg: dns.message.Message,
        timeout_s: float,
    ):
        return _fake_dns_response(msg), 1.0

    monkeypatch.setattr("resolver_inventory.validate.dns_plain._query_udp", fake_query_udp)

    candidate = _candidate()
    settings_python = _settings()
    python_results = validate_candidates([candidate], settings_python)
    assert len(python_results) == 1

    settings_massdns = _settings()
    settings_massdns.validation.dns_backend.kind = "massdns"
    settings_massdns.validation.dns_backend.massdns_bin = str(_make_fake_massdns(tmp_path))
    massdns_results = validate_candidates([candidate], settings_massdns)
    assert len(massdns_results) == 1

    assert python_results[0].status == massdns_results[0].status
    assert python_results[0].accepted == massdns_results[0].accepted
