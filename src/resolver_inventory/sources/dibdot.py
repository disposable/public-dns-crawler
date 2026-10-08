"""Source adapters for dibdot's DoH-IP-blocklists repository.

The project maintains an inventory of public DoH servers for blocklist
purposes; it doubles as a large discovery feed:

- ``doh-domains.txt`` lists confirmed DoH hostnames - emitted as
  ``https://<domain>/dns-query`` candidates.
- ``doh-ipv4.txt`` / ``doh-ipv6.txt`` list DoH server IPs annotated with
  ``# hostname`` comments - emitted as DoT candidates (hostname + bootstrap
  IPs so validation can rotate across the known addresses with proper SNI)
  and as additional ``https://<hostname>/dns-query`` guesses.

The lists aggregate many upstream inventories and include stale entries;
validation is expected to do the filtering.
"""

from __future__ import annotations

import ipaddress
import re

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger
from resolver_inventory.util.retry import fetch_url

logger = get_logger(__name__)

DIBDOT_BASE_URL = "https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master"

_DOMAINS_FILE = "doh-domains.txt"
_IP_LISTS = (("doh-ipv4.txt", 4), ("doh-ipv6.txt", 6))

DEFAULT_DOT_PORT = 853
_DOH_PATH = "/dns-query"

# Conservative hostname shape; entries without a dot (localhost-style names)
# or with invalid characters are dropped.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$"
)


def _valid_hostname(text: str) -> bool:
    return bool(_HOSTNAME_RE.match(text.strip().rstrip(".").lower()))


def _norm_hostname(text: str) -> str:
    return text.strip().rstrip(".").lower()


class _DibDotSource(BaseSource):
    """Fetch one or more blocklist text files from a base URL."""

    SOURCE_NAME = "dibdot"

    def _base_url(self) -> str:
        return (self.entry.url or self.entry.extra.get("url") or DIBDOT_BASE_URL).rstrip("/")

    def _fetch_file(self, name: str) -> str | None:
        url = f"{self._base_url()}/{name}"
        try:
            return fetch_url(url, timeout=30).decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("dibdot: fetch %s failed: %s", name, exc)
            return None

    def _domains(self) -> list[str]:
        """Hostnames from the domains list (one per line, comments ignored)."""
        data = self._fetch_file(_DOMAINS_FILE)
        if data is None:
            return []
        out: list[str] = []
        for line in data.splitlines():
            name, _, _ = line.partition("#")
            name = _norm_hostname(name)
            if name and _valid_hostname(name):
                out.append(name)
        return out

    def _hostname_addresses(self) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Map each commented hostname to its listed IPv4 / IPv6 literals."""
        v4: dict[str, list[str]] = {}
        v6: dict[str, list[str]] = {}
        for filename, version in _IP_LISTS:
            data = self._fetch_file(filename)
            if data is None:
                continue
            for line in data.splitlines():
                ip_part, _, comment = line.partition("#")
                ip_text = ip_part.strip()
                if not ip_text:
                    continue
                try:
                    addr = ipaddress.ip_address(ip_text)
                except ValueError:
                    continue
                if addr.version != version:
                    continue
                for raw_name in comment.split(","):
                    name = _norm_hostname(raw_name)
                    if not _valid_hostname(name):
                        continue
                    bucket = v4 if version == 4 else v6
                    listing = bucket.setdefault(name, [])
                    if str(addr) not in listing:
                        listing.append(str(addr))
        return v4, v6


def _doh_candidate(
    hostname: str,
    *,
    bootstrap_ipv4: list[str] | None = None,
    bootstrap_ipv6: list[str] | None = None,
) -> Candidate:
    return Candidate(
        provider=None,
        source=_DibDotSource.SOURCE_NAME,
        transport="doh",
        endpoint_url=f"https://{hostname}{_DOH_PATH}",
        host=hostname,
        port=443,
        path=_DOH_PATH,
        bootstrap_ipv4=bootstrap_ipv4 or [],
        bootstrap_ipv6=bootstrap_ipv6 or [],
        tls_server_name=hostname,
    )


class DibDotDohSource(_DibDotSource):
    """DoH candidates from the domains list and IP-list hostname comments."""

    def candidates(self) -> list[Candidate]:
        hostnames = set(self._domains())
        v4, v6 = self._hostname_addresses()
        hostnames.update(v4)
        hostnames.update(v6)
        results = [
            _doh_candidate(
                name,
                bootstrap_ipv4=sorted(v4.get(name, [])),
                bootstrap_ipv6=sorted(v6.get(name, [])),
            )
            for name in sorted(hostnames)
        ]
        logger.info("dibdot: found %d DoH endpoints", len(results))
        return results


class DibDotDotSource(_DibDotSource):
    """DoT candidates: each commented hostname with its listed IPs as bootstrap."""

    def candidates(self) -> list[Candidate]:
        v4, v6 = self._hostname_addresses()
        results: list[Candidate] = []
        for name in sorted(set(v4) | set(v6)):
            results.append(
                Candidate(
                    provider=None,
                    source=self.SOURCE_NAME,
                    transport="dot",
                    endpoint_url=None,
                    host=name,
                    port=DEFAULT_DOT_PORT,
                    path=None,
                    bootstrap_ipv4=sorted(v4.get(name, [])),
                    bootstrap_ipv6=sorted(v6.get(name, [])),
                    tls_server_name=name,
                )
            )
        logger.info("dibdot: found %d DoT endpoints", len(results))
        return results
