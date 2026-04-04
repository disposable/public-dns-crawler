"""Export helpers for generated probe corpus artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from resolver_inventory.probe_corpus.schema import ProbeCorpus, probe_corpus_to_dict


def write_probe_corpus_outputs(corpus: ProbeCorpus, output_dir: str | Path) -> None:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = probe_corpus_to_dict(corpus)
    (out_dir / "probe-corpus.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # JSON is valid YAML 1.2, which keeps this exporter dependency-free for now.
    (out_dir / "probe-corpus.yaml").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    metadata = {
        "schema_version": corpus.schema_version,
        "corpus_version": corpus.corpus_version,
        "generated_at": corpus.generated_at,
        "generator_version": corpus.generator_version,
        "sources_used": corpus.sources_used,
        "probe_counts": corpus.probe_counts,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (out_dir / "SUMMARY.md").write_text(build_summary_markdown(corpus), encoding="utf-8")


def build_summary_markdown(corpus: ProbeCorpus) -> str:
    lines = [
        "# Probe Corpus Summary",
        "",
        f"- Corpus version: `{corpus.corpus_version}`",
        f"- Schema version: `{corpus.schema_version}`",
        f"- Generator version: `{corpus.generator_version or 'unknown'}`",
        f"- Generated at: `{corpus.generated_at}`",
        "",
        "## Counts",
        "",
    ]
    for kind, count in sorted(corpus.probe_counts.items()):
        lines.append(f"- `{kind}`: {count}")
    lines.extend(["", "## Sources", ""])
    for source in corpus.sources_used:
        lines.append(f"- {source}")
    return "\n".join(lines) + "\n"
