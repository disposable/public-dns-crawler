"""DNS packet helpers using dnspython."""

from __future__ import annotations

import dns.message
import dns.name
import dns.rdatatype


def make_query(qname: str, rdtype: str = "A") -> bytes:
    """Build a wire-format DNS query."""
    msg = dns.message.make_query(
        qname,
        dns.rdatatype.from_text(rdtype),
        use_edns=True,
        want_dnssec=False,
    )
    msg.id = 0
    return msg.to_wire()


def parse_response(wire: bytes) -> dns.message.Message:
    """Parse wire-format DNS response."""
    return dns.message.from_wire(wire)


def response_has_answer(msg: dns.message.Message) -> bool:
    return len(msg.answer) > 0


def response_is_nxdomain(msg: dns.message.Message) -> bool:
    return msg.rcode() == dns.rcode.NXDOMAIN  # type: ignore[attr-defined]


def response_rcode_name(msg: dns.message.Message) -> str:
    return dns.rcode.to_text(msg.rcode())  # type: ignore[attr-defined]
