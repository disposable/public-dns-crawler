"""Source adapters for resolver discovery.

Public API::

    from resolver_inventory.sources import discover_candidates
"""

from __future__ import annotations

from resolver_inventory.models import Candidate, DiscoveryResult
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
    return discover_candidates_with_filtered(settings).candidates


def discover_candidates_with_filtered(settings: Settings) -> DiscoveryResult:
    """Aggregate candidates and keep a record of pre-validation filtering."""
    results: list[Candidate] = []
    filtered = []
    for entry in settings.sources.dns:
        cls = _DNS_SOURCE_MAP.get(entry.type)
        if cls is None:
            raise ValueError(f"Unknown dns source type: {entry.type!r}")
        source = cls(entry)
        results.extend(source.candidates())
        filtered.extend(source.filtered_candidates())
    for entry in settings.sources.doh:
        cls = _DOH_SOURCE_MAP.get(entry.type)
        if cls is None:
            raise ValueError(f"Unknown doh source type: {entry.type!r}")
        source = cls(entry)
        results.extend(source.candidates())
        filtered.extend(source.filtered_candidates())
    return DiscoveryResult(candidates=results, filtered=filtered)
