"""Export helpers for generated probe corpus artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from resolver_inventory.probe_corpus.models import GeneratedProbeCorpusResult
from resolver_inventory.probe_corpus.schema import probe_corpus_to_dict


def write_probe_corpus_outputs(result: GeneratedProbeCorpusResult, output_dir: str | Path) -> None:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus = result.corpus
    report = result.report
    payload = probe_corpus_to_dict(corpus)
    (out_dir / "probe-corpus.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    metadata = {
        "schema_version": corpus.schema_version,
        "corpus_version": corpus.corpus_version,
        "generated_at": corpus.generated_at,
        "generator_version": corpus.generator_version,
        "sources_used": corpus.sources_used,
        "candidate_counts": report.candidate_counts,
        "accepted_counts": report.accepted_counts,
        "rejected_counts": report.rejected_counts,
        "rejected_by_reason": report.rejected_by_reason,
        "baseline_resolvers_used": report.baseline_resolvers_used,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (out_dir / "SUMMARY.md").write_text(build_summary_markdown(result), encoding="utf-8")


def build_summary_markdown(result: GeneratedProbeCorpusResult) -> str:
    corpus = result.corpus
    report = result.report
    lines = [
        "# Probe Corpus Summary",
        "",
        f"- Corpus version: `{corpus.corpus_version}`",
        f"- Schema version: `{corpus.schema_version}`",
        f"- Generator version: `{corpus.generator_version or 'unknown'}`",
        f"- Generated at: `{corpus.generated_at}`",
        f"- Candidates seen: `{report.total_candidates}`",
        f"- Accepted probes: `{report.accepted_count}`",
        f"- Rejected probes: `{report.rejected_count}`",
        "",
        "## Accepted Counts",
        "",
    ]
    for kind, count in sorted(report.accepted_counts.items()):
        lines.append(f"- `{kind}`: {count}")
    lines.extend(["", "## Rejected By Reason", ""])
    if report.rejected_by_reason:
        for reason, count in sorted(report.rejected_by_reason.items()):
            lines.append(f"- `{reason}`: {count}")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Baseline Resolvers",
            "",
        ]
    )
    for resolver in report.baseline_resolvers_used:
        lines.append(f"- `{resolver}`")
    lines.extend(
        [
            "",
            "## Consensus Metadata",
            "",
            "- `expected_nameservers` is generation metadata captured from the accepted baseline",
            "  quorum.",
            "- Runtime validation for `consensus_match` still uses live baseline comparison.",
        ]
    )
    lines.extend(["", "## Dropped Seeds", ""])
    if report.rejected_candidates:
        for candidate, validation in report.rejected_candidates:
            lines.append(
                f"- `{candidate.original_seed}` -> `{validation.rejection_reason or 'unknown'}`"
            )
    else:
        lines.append("- none")
    lines.extend(["", "## Sources", ""])
    for source in corpus.sources_used:
        lines.append(f"- {source}")
    return "\n".join(lines) + "\n"
