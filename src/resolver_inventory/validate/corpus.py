"""Test corpus abstraction.

A corpus provides the questions and expected answers used during validation.
Three modes are supported:

* ``controlled`` - operator-owned zone with fixed RRs (best accuracy).
* ``fallback``   - low-variance public infrastructure queries.
* ``consensus``  - compared against a baseline resolver set (weakest).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from resolver_inventory.settings import CorpusConfig


@dataclass
class CorpusEntry:
    """A single test question."""

    qname: str
    rdtype: str
    expected_rcode: str = "NOERROR"
    expected_answers: list[str] = field(default_factory=list)
    nxdomain: bool = False
    label: str = ""


@dataclass
class Corpus:
    """Collection of corpus entries for a validation run."""

    positive: list[CorpusEntry] = field(default_factory=list)
    nxdomain: list[CorpusEntry] = field(default_factory=list)
    mode: str = "fallback"


_FALLBACK_POSITIVE: list[tuple[str, str]] = [
    ("a.root-servers.net.", "A"),
    ("b.root-servers.net.", "A"),
    ("c.root-servers.net.", "A"),
    ("ns1.iana.org.", "A"),
    ("ns2.iana.org.", "A"),
    ("l.root-servers.net.", "A"),
]

_FALLBACK_NXDOMAIN_LABELS: list[str] = [
    "this-label-does-not-exist-xyzzy.iana.org.",
    "nxtest-sentinel-abc123.root-servers.net.",
]


def build_corpus(config: CorpusConfig) -> Corpus:
    """Construct a Corpus from the given configuration."""
    if config.mode == "controlled" and config.zone:
        return _build_controlled_corpus(config.zone)
    return _build_fallback_corpus()


def _build_controlled_corpus(zone: str) -> Corpus:
    zone = zone.rstrip(".")
    positive = [
        CorpusEntry(qname=f"a.ok.{zone}.", rdtype="A", label="controlled-a"),
        CorpusEntry(qname=f"aaaa.ok.{zone}.", rdtype="AAAA", label="controlled-aaaa"),
        CorpusEntry(qname=f"txt.ok.{zone}.", rdtype="TXT", label="controlled-txt"),
        CorpusEntry(qname=f"cname.ok.{zone}.", rdtype="CNAME", label="controlled-cname"),
    ]
    nxdomain = [
        CorpusEntry(
            qname=f"nxtest-sentinel-xyzzy.{zone}.",
            rdtype="A",
            expected_rcode="NXDOMAIN",
            nxdomain=True,
            label="controlled-nx",
        )
    ]
    return Corpus(positive=positive, nxdomain=nxdomain, mode="controlled")


def _build_fallback_corpus() -> Corpus:
    positive = [
        CorpusEntry(qname=qname, rdtype=rdtype, label=f"fallback-{qname}")
        for qname, rdtype in _FALLBACK_POSITIVE
    ]
    nxdomain = [
        CorpusEntry(
            qname=qname,
            rdtype="A",
            expected_rcode="NXDOMAIN",
            nxdomain=True,
            label=f"fallback-nx-{qname}",
        )
        for qname in _FALLBACK_NXDOMAIN_LABELS
    ]
    return Corpus(positive=positive, nxdomain=nxdomain, mode="fallback")
