"""Plain-text resolver list exporter."""

from __future__ import annotations

from pathlib import Path

from resolver_inventory.models import ValidationResult


def export_text(
    results: list[ValidationResult],
    *,
    accepted_only: bool = True,
    path: str | Path | None = None,
    include_doh: bool = False,
) -> str:
    """Export resolver list as newline-separated IPs or URLs.

    Classic DNS resolvers emit ``host:port`` lines.
    By default this exports plain DNS resolvers only. Set *include_doh* to export
    DoH resolvers instead.
    Returns the text. If *path* is given, also writes it to disk.
    """
    records = [r for r in results if r.accepted] if accepted_only else results
    lines: list[str] = []
    for r in records:
        c = r.candidate
        if c.transport in ("dns-udp", "dns-tcp") and not include_doh:
            lines.append(f"{c.host}:{c.port}")
        elif c.transport == "doh" and include_doh:
            lines.append(c.endpoint_url or f"https://{c.host}:{c.port}{c.path}")

    seen: set[str] = set()
    deduped: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            deduped.append(line)

    text = "\n".join(deduped) + ("\n" if deduped else "")
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return text
