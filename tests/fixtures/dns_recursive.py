"""A deliberately broken/spoofing DNS fixture for negative integration tests.

Spoofs all NXDOMAIN responses as NOERROR with a fake A record, simulating
a resolver that captures NXDOMAIN for ad injection.
"""

from __future__ import annotations

import dnslib
import dnslib.server

SPOOFED_IP = "192.0.2.99"


class _SpoofingResolver(dnslib.server.BaseResolver):  # type: ignore[misc]
    """Returns NOERROR + a fake A record for every query, even NXDOMAINs."""

    def resolve(
        self, request: dnslib.DNSRecord, handler: dnslib.server.DNSHandler
    ) -> dnslib.DNSRecord:
        reply = request.reply()
        reply.add_answer(
            dnslib.RR(
                rname=request.q.qname,
                rtype=dnslib.QTYPE.A,
                rclass=dnslib.CLASS.IN,
                ttl=60,
                rdata=dnslib.A(SPOOFED_IP),
            )
        )
        return reply


class _WrongAnswerResolver(dnslib.server.BaseResolver):  # type: ignore[misc]
    """Returns NOERROR but with the wrong A record for every query."""

    def resolve(
        self, request: dnslib.DNSRecord, handler: dnslib.server.DNSHandler
    ) -> dnslib.DNSRecord:
        reply = request.reply()
        reply.add_answer(
            dnslib.RR(
                rname=request.q.qname,
                rtype=dnslib.QTYPE.A,
                rclass=dnslib.CLASS.IN,
                ttl=60,
                rdata=dnslib.A("10.255.255.1"),
            )
        )
        return reply


class SpoofingDnsFixture:
    """DNS server that spoofs all NXDOMAIN as NOERROR."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self._server: dnslib.server.DNSServer | None = None

    def start(self) -> None:
        self._server = dnslib.server.DNSServer(
            _SpoofingResolver(),
            address=self.host,
            port=self._requested_port,
            tcp=False,
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

    def __enter__(self) -> SpoofingDnsFixture:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
