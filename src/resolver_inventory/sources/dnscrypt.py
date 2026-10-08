"""Source adapter for DNSCrypt-format public resolver lists (sdns:// stamps).

Parses the v3 public-resolvers.md format published by the DNSCrypt project:
provider sections introduced by ``## <name>`` headings, each containing one or
more ``sdns://`` stamps. Stamps are decoded per the DNS Stamps specification
(https://dnscrypt.info/stamps-specifications/) - only protocol identifiers we
can actually validate are emitted (plain DNS, DoH, DoT, DoQ); DNSCrypt and
oblivious-DoH stamps are skipped.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger
from resolver_inventory.util.retry import fetch_url

logger = get_logger(__name__)

DNSCRYPT_RESOLVERS_URL = (
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md"
)

_HEADING_RE = re.compile(r"^##\s+(?P<provider>.+?)\s*$")
_STAMP_RE = re.compile(r"sdns://(?P<stamp>[A-Za-z0-9_-]+)")

PROTO_PLAIN = 0x00
PROTO_DNSCRYPT = 0x01
PROTO_DOH = 0x02
PROTO_DOT = 0x03
PROTO_DOQ = 0x04


class _StampError(ValueError):
    """A single stamp is malformed; the source must keep going."""


def _lp(raw: bytes, off: int) -> tuple[bytes, int]:
    """Read a length-prefixed field: <len byte> || <len bytes>."""
    if off >= len(raw):
        raise _StampError("truncated length-prefixed field")
    ln = raw[off]
    off += 1
    if off + ln > len(raw):
        raise _StampError("length-prefixed field overruns stamp")
    return raw[off : off + ln], off + ln


def _vlp(raw: bytes, off: int) -> tuple[list[bytes], int]:
    """Read a VLP: LP items; a length byte with bit 0x80 marks a non-final item."""
    items: list[bytes] = []
    while True:
        if off >= len(raw):
            raise _StampError("truncated VLP")
        more = bool(raw[off] & 0x80)
        ln = raw[off] & 0x7F
        off += 1
        if off + ln > len(raw):
            raise _StampError("VLP item overruns stamp")
        items.append(raw[off : off + ln])
        off += ln
        if not more:
            return items, off


def _text(item: bytes) -> str:
    try:
        return item.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _StampError(f"non-UTF-8 field: {exc}") from exc


def _parse_port(text: str) -> int:
    try:
        port = int(text)
    except ValueError as exc:
        raise _StampError(f"invalid port {text!r}") from exc
    if not 1 <= port <= 65535:
        raise _StampError(f"port out of range: {port}")
    return port


def _split_host_port(text: str, default_port: int) -> tuple[str, int]:
    """Split ``host[:port]`` / ``[v6][:port]`` stamp fields."""
    text = text.strip()
    if not text:
        raise _StampError("empty host field")
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise _StampError(f"unbalanced IPv6 bracket in {text!r}")
        host = text[1:close]
        rest = text[close + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise _StampError(f"unexpected suffix after bracket in {text!r}")
        return host, _parse_port(rest[1:])
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        if host:
            return host, _parse_port(port_text)
    # Bare host or unbracketed IPv6 (spec requires brackets, tolerate both).
    return text, default_port


class _Stamp:
    __slots__ = ("addr", "hostname", "path", "port", "proto")

    def __init__(
        self,
        proto: int,
        addr: str,
        hostname: str,
        port: int,
        path: str,
    ) -> None:
        self.proto = proto
        self.addr = addr
        self.hostname = hostname
        self.port = port
        self.path = path


def _decode_stamp(encoded: str) -> _Stamp:
    """Decode one ``sdns://`` payload. Raises _StampError on any malformed input."""
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding)
    except (binascii.Error, ValueError) as exc:
        raise _StampError(f"invalid base64url: {exc}") from exc
    if len(raw) < 9:
        raise _StampError("stamp too short")

    proto = raw[0]
    off = 9  # 1 byte proto + 8 byte little-endian props

    if proto == PROTO_PLAIN:
        addr_field, off = _lp(raw, off)
        host, port = _split_host_port(_text(addr_field), 53)
        return _Stamp(proto, host, "", port, "")

    if proto in (PROTO_DOH, PROTO_DOT, PROTO_DOQ):
        addr_field, off = _lp(raw, off)
        addr = _text(addr_field).strip()
        if addr:
            addr, _ = _split_host_port(addr, 0)
        _hashes, off = _vlp(raw, off)
        hostname_field, off = _lp(raw, off)
        # Per the stamps spec an omitted :port in the hostname field means
        # 443 for DoH, DoT, and DoQ alike (not the usual 853 for DoT/DoQ).
        hostname, port = _split_host_port(_text(hostname_field), 443)
        if not hostname:
            raise _StampError("missing hostname")
        path = ""
        if proto == PROTO_DOH:
            path_field, off = _lp(raw, off)
            path = _text(path_field)
            if not path.startswith("/"):
                raise _StampError(f"invalid path {path!r}")
        # bootstrap items are plain-DNS resolvers for resolving the hostname
        # (not server addresses), so we decode to validate structure but do
        # not propagate them into Candidate.bootstrap_*.
        if off < len(raw):
            _vlp(raw, off)
        return _Stamp(proto, addr, hostname, port, path)

    raise _StampError(f"unsupported protocol id 0x{proto:02x}")


def _classify_addr(addr: str) -> tuple[str | None, str | None]:
    """Split an IP literal into (ipv4, ipv6); returns (None, None) otherwise."""
    try:
        parsed = ipaddress.ip_address(addr)
    except ValueError:
        return None, None
    return (str(parsed), None) if parsed.version == 4 else (None, str(parsed))


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


class _DnsCryptListSource(BaseSource):
    """Fetch a DNSCrypt v3 resolver list and yield candidates of one family.

    ``entry.url`` points at any file in the same format (public-resolvers.md,
    parental-control.md, opennic.md, ...); ``entry.extra["label"]`` overrides
    the ``source`` tag so sibling lists keep distinct provenance.
    """

    SOURCE_NAME = "dnscrypt"

    def _source_name(self) -> str:
        return str(self.entry.extra.get("label") or self.SOURCE_NAME)

    def candidates(self) -> list[Candidate]:
        url = self.entry.url or self.entry.extra.get("url") or DNSCRYPT_RESOLVERS_URL
        try:
            data = fetch_url(url, timeout=30).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("dnscrypt fetch failed: %s", exc)
            return []

        source_name = self._source_name()
        current_provider: str | None = None
        seen: set[tuple[str, str, int, str]] = set()
        results: list[Candidate] = []
        skipped = 0
        for line in data.splitlines():
            stripped = line.strip()
            heading = _HEADING_RE.match(stripped)
            if heading:
                current_provider = heading.group("provider").strip()
                continue
            for stamp_text in _STAMP_RE.findall(stripped):
                try:
                    stamp = _decode_stamp(stamp_text)
                except _StampError as exc:
                    skipped += 1
                    logger.debug("dnscrypt: skipping stamp: %s", exc)
                    continue
                for candidate in self._candidates_for(stamp, current_provider, source_name):
                    key = (
                        candidate.transport,
                        candidate.host,
                        candidate.port,
                        candidate.path or "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(candidate)
        logger.info(
            "%s: found %d candidates (%d stamps skipped)",
            source_name,
            len(results),
            skipped,
        )
        return results

    def _candidates_for(
        self, stamp: _Stamp, provider: str | None, source_name: str
    ) -> list[Candidate]:
        raise NotImplementedError

    def _addr_bootstrap(self, stamp: _Stamp) -> tuple[list[str], list[str]]:
        """Bootstrap addresses from the stamp's addr field (server IP)."""
        v4, v6 = _classify_addr(stamp.addr)
        return ([v4] if v4 else []), ([v6] if v6 else [])


class DnsCryptDnsSource(_DnsCryptListSource):
    """Plain-DNS (proto 0x00) entries from a DNSCrypt resolver list."""

    def _candidates_for(
        self, stamp: _Stamp, provider: str | None, source_name: str
    ) -> list[Candidate]:
        if stamp.proto != PROTO_PLAIN:
            return []
        ip4, ip6 = _classify_addr(stamp.addr)
        if ip4 is None and ip6 is None:
            return []
        return [
            Candidate(
                provider=provider,
                source=source_name,
                transport=transport,  # type: ignore[arg-type]
                endpoint_url=None,
                host=stamp.addr,
                port=stamp.port,
                path=None,
            )
            for transport in ("dns-udp", "dns-tcp")
        ]


def _tls_candidates(
    stamp: _Stamp,
    provider: str | None,
    proto: int,
    transport: str,
    source_name: str,
) -> list[Candidate]:
    """Emit a candidate for DoT/DoQ stamps (identical wire layout)."""
    if stamp.proto != proto:
        return []
    v4, v6 = _classify_addr(stamp.addr)
    return [
        Candidate(
            provider=provider,
            source=source_name,
            transport=transport,  # type: ignore[arg-type]
            endpoint_url=None,
            host=stamp.hostname,
            port=stamp.port,
            path=None,
            bootstrap_ipv4=[v4] if v4 else [],
            bootstrap_ipv6=[v6] if v6 else [],
            tls_server_name=stamp.hostname,
        )
    ]


class DnsCryptDohSource(_DnsCryptListSource):
    """DoH (proto 0x02) entries from a DNSCrypt resolver list."""

    def _candidates_for(
        self, stamp: _Stamp, provider: str | None, source_name: str
    ) -> list[Candidate]:
        if stamp.proto != PROTO_DOH:
            return []
        v4, v6 = _classify_addr(stamp.addr)
        return [
            Candidate(
                provider=provider,
                source=source_name,
                transport="doh",
                endpoint_url=(f"https://{_url_host(stamp.hostname)}:{stamp.port}{stamp.path}"),
                host=stamp.hostname,
                port=stamp.port,
                path=stamp.path,
                bootstrap_ipv4=[v4] if v4 else [],
                bootstrap_ipv6=[v6] if v6 else [],
                tls_server_name=stamp.hostname,
            )
        ]


class DnsCryptDotSource(_DnsCryptListSource):
    """DoT (proto 0x03) entries from a DNSCrypt resolver list."""

    def _candidates_for(
        self, stamp: _Stamp, provider: str | None, source_name: str
    ) -> list[Candidate]:
        return _tls_candidates(stamp, provider, PROTO_DOT, "dot", source_name)


class DnsCryptDoqSource(_DnsCryptListSource):
    """DoQ (proto 0x04) entries from a DNSCrypt resolver list."""

    def _candidates_for(
        self, stamp: _Stamp, provider: str | None, source_name: str
    ) -> list[Candidate]:
        return _tls_candidates(stamp, provider, PROTO_DOQ, "doq", source_name)
