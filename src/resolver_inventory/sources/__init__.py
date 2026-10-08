"""Source adapters for resolver discovery.

Public API::

    from resolver_inventory.sources import discover_candidates
"""

from __future__ import annotations

from resolver_inventory.models import Candidate, DiscoveryResult
from resolver_inventory.settings import Settings, SourceEntry
from resolver_inventory.sources.adguard import AdGuardDnsSource, AdGuardSource
from resolver_inventory.sources.curl_wiki import CurlWikiSource
from resolver_inventory.sources.dibdot import DibDotDohSource, DibDotDotSource
from resolver_inventory.sources.dnscrypt import (
    DnsCryptDnsSource,
    DnsCryptDohSource,
    DnsCryptDoqSource,
    DnsCryptDotSource,
)
from resolver_inventory.sources.doq import AdGuardDoqSource, ManualDoqSource
from resolver_inventory.sources.dot import AdGuardDotSource, ManualDotSource
from resolver_inventory.sources.manual import ManualDnsSource, ManualDohSource
from resolver_inventory.sources.paulmillr import (
    PaulMillrDnsSource,
    PaulMillrDohSource,
    PaulMillrDotSource,
)
from resolver_inventory.sources.publicdns_info import PublicDnsInfoSource

_DNS_SOURCE_MAP = {
    "manual": ManualDnsSource,
    "publicdns_info": PublicDnsInfoSource,
    "adguard": AdGuardDnsSource,
    "dnscrypt": DnsCryptDnsSource,
    "paulmillr": PaulMillrDnsSource,
}

_DOH_SOURCE_MAP = {
    "manual": ManualDohSource,
    "curl_wiki": CurlWikiSource,
    "adguard": AdGuardSource,
    "dnscrypt": DnsCryptDohSource,
    "paulmillr": PaulMillrDohSource,
    "dibdot": DibDotDohSource,
}

_DOT_SOURCE_MAP = {
    "manual": ManualDotSource,
    "adguard": AdGuardDotSource,
    "dnscrypt": DnsCryptDotSource,
    "paulmillr": PaulMillrDotSource,
    "dibdot": DibDotDotSource,
}

_DOQ_SOURCE_MAP = {
    "manual": ManualDoqSource,
    "adguard": AdGuardDoqSource,
    "dnscrypt": DnsCryptDoqSource,
}


def _build_source(entry: SourceEntry, family: str) -> list[Candidate]:
    registry = {
        "dns": _DNS_SOURCE_MAP,
        "doh": _DOH_SOURCE_MAP,
        "dot": _DOT_SOURCE_MAP,
        "doq": _DOQ_SOURCE_MAP,
    }.get(family)
    if registry is None:
        raise ValueError(f"Unknown source family: {family!r}")
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
    for entry in settings.sources.dot:
        cls = _DOT_SOURCE_MAP.get(entry.type)
        if cls is None:
            raise ValueError(f"Unknown dot source type: {entry.type!r}")
        source = cls(entry)
        results.extend(source.candidates())
        filtered.extend(source.filtered_candidates())
    for entry in settings.sources.doq:
        cls = _DOQ_SOURCE_MAP.get(entry.type)
        if cls is None:
            raise ValueError(f"Unknown doq source type: {entry.type!r}")
        source = cls(entry)
        results.extend(source.candidates())
        filtered.extend(source.filtered_candidates())
    return DiscoveryResult(candidates=results, filtered=filtered)
