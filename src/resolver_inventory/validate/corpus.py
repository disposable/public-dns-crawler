"""Test corpus abstraction."""

from __future__ import annotations

import json
import secrets
import string
from dataclasses import dataclass, field
from pathlib import Path

from resolver_inventory.settings import CorpusConfig
from resolver_inventory.validate.corpus_schema import (
    CorpusSchemaError,
    ProbeCorpus,
    ProbeDefinition,
    parse_probe_corpus,
)


@dataclass
class CorpusEntry:
    """A single test question."""

    rdtype: str
    qname: str | None = None
    qname_template: str | None = None
    expected_mode: str = "consensus_match"
    expected_rcode: str = "NOERROR"
    expected_answers: list[str] = field(default_factory=list)
    expected_nameservers: list[str] = field(default_factory=list)
    parent_zone: str | None = None
    nxdomain: bool = False
    label: str = ""
    source: str | None = None
    stability_score: float | None = None
    notes: str | None = None

    def render_qname(self, *, label_length: int = 40) -> str:
        if self.qname:
            return self.qname
        if not self.qname_template:
            raise CorpusSchemaError("probe entry is missing both qname and qname_template")
        return self.qname_template.format(uuid=_random_label(label_length))


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
    if config.mode == "controlled":
        if not config.zone:
            raise ValueError("controlled corpus mode requires validation.corpus.zone")
        return build_controlled_corpus(config.zone)
    if config.mode == "fallback":
        return build_builtin_fallback_corpus()
    if config.mode == "external":
        try:
            if not config.path:
                raise ValueError("external corpus mode requires validation.corpus.path")
            return load_external_corpus(
                config.path,
                required_schema_version=config.schema_version,
                strict=config.strict,
            )
        except Exception:
            if config.allow_builtin_fallback:
                return build_builtin_fallback_corpus()
            raise
    raise ValueError(f"unsupported corpus mode: {config.mode}")


def build_controlled_corpus(zone: str) -> Corpus:
    zone = zone.rstrip(".")
    positive = [
        CorpusEntry(
            qname=f"a.ok.{zone}.",
            rdtype="A",
            expected_mode="exact_rrset",
            expected_answers=["192.0.2.1"],
            label="controlled-a",
        ),
        CorpusEntry(
            qname=f"aaaa.ok.{zone}.",
            rdtype="AAAA",
            expected_mode="exact_rrset",
            expected_answers=["2001:db8::1"],
            label="controlled-aaaa",
        ),
        CorpusEntry(
            qname=f"txt.ok.{zone}.",
            rdtype="TXT",
            expected_mode="exact_rrset",
            expected_answers=['"v=test1"'],
            label="controlled-txt",
        ),
        CorpusEntry(
            qname=f"cname.ok.{zone}.",
            rdtype="CNAME",
            expected_mode="exact_rrset",
            expected_answers=[f"a.ok.{zone}."],
            label="controlled-cname",
        ),
    ]
    nxdomain = [
        CorpusEntry(
            qname=f"nxtest-sentinel-xyzzy.{zone}.",
            rdtype="A",
            expected_mode="nxdomain",
            expected_rcode="NXDOMAIN",
            parent_zone=f"{zone}.",
            nxdomain=True,
            label="controlled-nx",
        )
    ]
    return Corpus(positive=positive, nxdomain=nxdomain, mode="controlled")


def build_builtin_fallback_corpus() -> Corpus:
    positive = [
        CorpusEntry(
            qname=qname,
            rdtype=rdtype,
            expected_mode="consensus_match",
            label=f"fallback-{qname}",
        )
        for qname, rdtype in _FALLBACK_POSITIVE
    ]
    nxdomain = [
        CorpusEntry(
            qname=qname,
            rdtype="A",
            expected_mode="nxdomain",
            expected_rcode="NXDOMAIN",
            nxdomain=True,
            label=f"fallback-nx-{qname}",
        )
        for qname in _FALLBACK_NXDOMAIN_LABELS
    ]
    return Corpus(positive=positive, nxdomain=nxdomain, mode="fallback")


def load_external_corpus(
    path: str | Path,
    required_schema_version: int | None = None,
    strict: bool = True,
) -> Corpus:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    parsed = parse_probe_corpus(
        raw,
        required_schema_version=required_schema_version,
        strict=strict,
    )
    return _probe_corpus_to_internal(parsed)


def _probe_corpus_to_internal(parsed: ProbeCorpus) -> Corpus:
    positive: list[CorpusEntry] = []
    nxdomain: list[CorpusEntry] = []

    for probe in parsed.probes:
        entry = _to_corpus_entry(probe)
        if probe.expected_mode == "nxdomain":
            nxdomain.append(entry)
        else:
            positive.append(entry)

    return Corpus(positive=positive, nxdomain=nxdomain, mode="external")


def _to_corpus_entry(probe: ProbeDefinition) -> CorpusEntry:
    is_nxdomain = probe.expected_mode == "nxdomain"
    return CorpusEntry(
        qname=probe.qname,
        qname_template=probe.qname_template,
        rdtype=probe.qtype,
        expected_mode=probe.expected_mode,
        expected_rcode="NXDOMAIN" if is_nxdomain else "NOERROR",
        expected_answers=list(probe.expected_answers),
        expected_nameservers=list(probe.expected_nameservers),
        parent_zone=probe.parent_zone,
        nxdomain=is_nxdomain,
        label=probe.id,
        source=probe.source,
        stability_score=probe.stability_score,
        notes=probe.notes,
    )


def _random_label(label_length: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(alphabet[b % len(alphabet)] for b in secrets.token_bytes(label_length))
