"""Local authoritative DNS fixture using dnslib.

Serves a small in-memory zone that matches the controlled corpus entries:

    a.ok.test.local.      A     192.0.2.1
    aaaa.ok.test.local.   AAAA  2001:db8::1
    txt.ok.test.local.    TXT   "v=test1"
    cname.ok.test.local.  CNAME a.ok.test.local.

Any other name under test.local. returns NXDOMAIN.
Names outside test.local. are refused (SERVFAIL) to avoid confusion.
"""

from __future__ import annotations

import threading
from typing import Any

import dnslib
import dnslib.server

ZONE_NAME = "test.local."
ZONE_RECORDS: list[tuple[str, str, Any]] = [
    ("a.ok.test.local.", "A", "192.0.2.1"),
    ("aaaa.ok.test.local.", "AAAA", "2001:db8::1"),
    ("txt.ok.test.local.", "TXT", b"v=test1"),
    ("cname.ok.test.local.", "CNAME", "a.ok.test.local."),
]
NXDOMAIN_LABEL = "nxtest-sentinel-xyzzy.test.local."


class _AuthResolver(dnslib.server.BaseResolver):  # type: ignore[misc]
    def __init__(self) -> None:
        self._records: dict[tuple[str, int], list[Any]] = {}
        for name, rtype, rdata in ZONE_RECORDS:
            key = (name.lower(), getattr(dnslib.QTYPE, rtype))
            entry: Any
            if rtype == "A":
                entry = dnslib.A(rdata)
            elif rtype == "AAAA":
                entry = dnslib.AAAA(rdata)
            elif rtype == "TXT":
                entry = dnslib.TXT(rdata)
            elif rtype == "CNAME":
                entry = dnslib.CNAME(rdata)
            else:
                continue
            self._records.setdefault(key, []).append(entry)

    def resolve(
        self, request: dnslib.DNSRecord, handler: dnslib.server.DNSHandler
    ) -> dnslib.DNSRecord:
        reply = request.reply()
        qname = str(request.q.qname).lower()
        qtype = request.q.qtype

        if not qname.endswith(ZONE_NAME.lower()):
            reply.header.rcode = dnslib.RCODE.SERVFAIL
            return reply

        key = (qname, qtype)
        records = self._records.get(key)

        if records is None:
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            return reply

        for rdata in records:
            reply.add_answer(
                dnslib.RR(
                    rname=request.q.qname,
                    rtype=qtype,
                    rclass=dnslib.CLASS.IN,
                    ttl=60,
                    rdata=rdata,
                )
            )
        return reply


class AuthoritativeDnsFixture:
    """Manages a local authoritative DNS server for testing."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self._server: dnslib.server.DNSServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        resolver = _AuthResolver()
        self._server = dnslib.server.DNSServer(
            resolver,
            address=self.host,
            port=self._requested_port,
            tcp=False,
        )
        self._server.start_thread()
        # Retrieve the actual bound port
        if self._server.server and hasattr(self._server.server, "server_address"):
            self.port = self._server.server.server_address[1]
        else:
            self.port = self._requested_port

    def stop(self) -> None:
        if self._server:
            self._server.stop()
            self._server = None

    def __enter__(self) -> AuthoritativeDnsFixture:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


class AuthoritativeTcpDnsFixture:
    """TCP-only authoritative fixture (same zone)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self._server: dnslib.server.DNSServer | None = None

    def start(self) -> None:
        resolver = _AuthResolver()
        self._server = dnslib.server.DNSServer(
            resolver,
            address=self.host,
            port=self._requested_port,
            tcp=True,
        )
        self._server.start_thread()
        if self._server.server and hasattr(self._server.server, "server_address"):
            self.port = self._server.server.server_address[1]
        else:
            self.port = self._requested_port

    def stop(self) -> None:
        if self._server:
            self._server.stop()
            self._server = None

    def __enter__(self) -> AuthoritativeTcpDnsFixture:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
