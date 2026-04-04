"""Source adapters for resolver discovery.

Public API::

    from resolver_inventory.sources import discover_candidates
"""

from __future__ import annotations

from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings, SourceEntry
from resolver_inventory.sources.adguard import AdGuardSource
from resolver_inventory.sources.curl_wiki import CurlWikiSource
from resolver_inventory.sources.manual import ManualDnsSource, ManualDohSource
from resolver_inventory.sources.publicdns_info import PublicDnsInfoSource

_DNS_SOURCE_MAP = {
    "manual": ManualDnsSource,
    "publicdns_info": PublicDnsInfoSource,
}

_DOH_SOURCE_MAP = {
    "manual": ManualDohSource,
    "curl_wiki": CurlWikiSource,
    "adguard": AdGuardSource,
}


def _build_source(entry: SourceEntry, family: str) -> list[Candidate]:
    registry = _DNS_SOURCE_MAP if family == "dns" else _DOH_SOURCE_MAP
    cls = registry.get(entry.type)
    if cls is None:
        raise ValueError(f"Unknown {family} source type: {entry.type!r}")
    return cls(entry).candidates()


def discover_candidates(settings: Settings) -> list[Candidate]:
    """Aggregate candidates from all configured sources."""
    results: list[Candidate] = []
    for entry in settings.sources.dns:
        results.extend(_build_source(entry, "dns"))
    for entry in settings.sources.doh:
        results.extend(_build_source(entry, "doh"))
    return results
