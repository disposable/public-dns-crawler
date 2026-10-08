"""Plain-text resolver list exporter."""

from __future__ import annotations

from pathlib import Path

from resolver_inventory.models import ValidationResult

_PLAIN_TRANSPORTS = ("dns-udp", "dns-tcp")


def _format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _format_dot_endpoint(host: str, port: int, tls_server_name: str | None) -> str:
    """Render a DoT endpoint as ``tls://host[:port][#tls_name]``.

    The ``#name`` suffix carries the TLS authentication name when it differs
    from the connect host (for example an IP endpoint with a certificate
    name), matching the ``host#name`` convention used by Unbound and
    systemd-resolved.
    """
    display_host = f"[{host}]" if ":" in host else host
    suffix = f":{port}" if port != 853 else ""
    name_suffix = ""
    if tls_server_name and tls_server_name != host:
        name_suffix = f"#{tls_server_name}"
    return f"tls://{display_host}{suffix}{name_suffix}"


def export_text(
    results: list[ValidationResult],
    *,
    accepted_only: bool = True,
    path: str | Path | None = None,
    include_doh: bool = False,
    transport: str | None = None,
) -> str:
    """Export resolver list as newline-separated endpoints.

    Output depends on *transport*:

    - ``"dns"`` (default): plain DNS resolvers as ``host:port``
    - ``"doh"``: DoH resolvers as full HTTPS endpoint URLs
    - ``"dot"``: DoT resolvers as ``tls://host[:port][#name]``

    *include_doh* is a deprecated alias for ``transport="doh"``.
    Returns the text. If *path* is given, also writes it to disk.
    """
    if transport is None:
        transport = "doh" if include_doh else "dns"
    records = [r for r in results if r.accepted] if accepted_only else results
    lines: list[str] = []
    for r in records:
        c = r.candidate
        if c.transport in _PLAIN_TRANSPORTS and transport == "dns":
            lines.append(_format_host_port(c.host, c.port))
        elif c.transport == "doh" and transport == "doh":
            lines.append(c.endpoint_url or f"https://{c.host}:{c.port}{c.path}")
        elif c.transport == "dot" and transport == "dot":
            lines.append(_format_dot_endpoint(c.host, c.port, c.tls_server_name))

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
