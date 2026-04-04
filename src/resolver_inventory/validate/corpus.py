"""Test corpus abstraction."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

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


def build_builtin_fallback_corpus() -> Corpus:
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
    qname = probe.qname or _render_qname_template(probe.qname_template)
    is_nxdomain = probe.expected_mode == "nxdomain"
    return CorpusEntry(
        qname=qname,
        rdtype=probe.qtype,
        expected_rcode="NXDOMAIN" if is_nxdomain else "NOERROR",
        expected_answers=list(probe.expected_answers),
        nxdomain=is_nxdomain,
        label=probe.id,
    )


def _render_qname_template(template: str | None) -> str:
    if not template:
        raise CorpusSchemaError("probe entry is missing both qname and qname_template")
    try:
        return template.format(uuid=uuid4().hex)
    except KeyError as exc:
        raise CorpusSchemaError(f"unsupported qname_template placeholder '{exc.args[0]}'") from exc
