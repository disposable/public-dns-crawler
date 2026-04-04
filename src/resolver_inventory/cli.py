"""Command-line interface for resolver-inventory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from resolver_inventory.util.logging import configure_logging, get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------


def cmd_discover(args: argparse.Namespace) -> int:
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates

    settings = load_settings(args.config)
    candidates = discover_candidates(settings)
    dns_c = normalize_dns_candidates(candidates)
    doh_c = normalize_doh_candidates(candidates)
    all_c = dns_c + doh_c
    logger.info("Discovered %d candidates (%d DNS, %d DoH)", len(all_c), len(dns_c), len(doh_c))

    if args.output:
        import json

        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "provider": c.provider,
                "source": c.source,
                "transport": c.transport,
                "host": c.host,
                "port": c.port,
                "endpoint_url": c.endpoint_url,
                "path": c.path,
            }
            for c in all_c
        ]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote candidates to %s", args.output)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    import json

    from resolver_inventory.export.json import export_json
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates
    from resolver_inventory.validate import validate_candidates

    settings = load_settings(args.config)

    if args.input:
        raw = json.loads(Path(args.input).read_text())
        from resolver_inventory.models import Candidate

        candidates = [
            Candidate(
                provider=r.get("provider"),
                source=r.get("source", "loaded"),
                transport=r["transport"],
                endpoint_url=r.get("endpoint_url"),
                host=r["host"],
                port=r["port"],
                path=r.get("path"),
            )
            for r in raw
        ]
    else:
        raw_candidates = discover_candidates(settings)
        candidates = normalize_dns_candidates(raw_candidates) + normalize_doh_candidates(
            raw_candidates
        )

    logger.info("Validating %d candidates…", len(candidates))
    results = validate_candidates(candidates, settings)

    accepted = sum(1 for r in results if r.status == "accepted")
    candidate_count = sum(1 for r in results if r.status == "candidate")
    rejected = sum(1 for r in results if r.status == "rejected")
    logger.info(
        "Results: %d accepted, %d candidate, %d rejected",
        accepted,
        candidate_count,
        rejected,
    )

    out_path = args.output or "outputs/validated.json"
    export_json(results, accepted_only=False, path=out_path)
    logger.info("Wrote results to %s", out_path)
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    """Full pipeline: discover → validate → export all formats."""
    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.normalize.dns import normalize_dns_candidates
    from resolver_inventory.normalize.doh import normalize_doh_candidates
    from resolver_inventory.settings import load_settings
    from resolver_inventory.sources import discover_candidates
    from resolver_inventory.validate import validate_candidates

    settings = load_settings(args.config)
    out_dir = Path(args.output or settings.export.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw = discover_candidates(settings)
    candidates = normalize_dns_candidates(raw) + normalize_doh_candidates(raw)
    logger.info("Discovered %d normalized candidates", len(candidates))

    results = validate_candidates(candidates, settings)
    accepted = [r for r in results if r.accepted]
    logger.info("%d/%d candidates accepted", len(accepted), len(results))

    formats = settings.export.formats
    if "json" in formats:
        export_json(results, accepted_only=False, path=out_dir / "validated.json")
        export_json(results, accepted_only=True, path=out_dir / "accepted.json")
    if "text" in formats:
        export_text(results, path=out_dir / "resolvers.txt")
        export_text(results, include_doh=True, path=out_dir / "resolvers-doh.txt")
    if "dnsdist" in formats:
        export_dnsdist(results, path=out_dir / "dnsdist.conf")
    if "unbound" in formats:
        export_unbound(results, path=out_dir / "unbound-forward.conf")

    logger.info("Outputs written to %s", out_dir)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    import json

    from resolver_inventory.export.dnsdist import export_dnsdist
    from resolver_inventory.export.json import export_json
    from resolver_inventory.export.text import export_text
    from resolver_inventory.export.unbound import export_unbound
    from resolver_inventory.models import Candidate, ProbeResult, ValidationResult

    in_path = args.input or "outputs/validated.json"

    try:
        raw_results = json.loads(Path(in_path).read_text())
    except FileNotFoundError:
        logger.error("Input file not found: %s — run 'validate' first", in_path)
        return 1

    results: list[ValidationResult] = []
    for item in raw_results:
        c_data = item["candidate"]
        candidate = Candidate(
            provider=c_data.get("provider"),
            source=c_data.get("source", "loaded"),
            transport=c_data["transport"],
            endpoint_url=c_data.get("endpoint_url"),
            host=c_data["host"],
            port=c_data["port"],
            path=c_data.get("path"),
            bootstrap_ipv4=c_data.get("bootstrap_ipv4", []),
            bootstrap_ipv6=c_data.get("bootstrap_ipv6", []),
            tls_server_name=c_data.get("tls_server_name"),
            metadata=c_data.get("metadata", {}),
        )
        probes = [
            ProbeResult(
                ok=p["ok"],
                probe=p["probe"],
                latency_ms=p.get("latency_ms"),
                error=p.get("error"),
                details=p.get("details", {}),
            )
            for p in item.get("probes", [])
        ]
        results.append(
            ValidationResult(
                candidate=candidate,
                accepted=item["accepted"],
                score=item["score"],
                status=item["status"],
                reasons=item["reasons"],
                probes=probes,
            )
        )

    fmt = args.format
    out = args.output

    if fmt == "json":
        text = export_json(results, path=out)
    elif fmt == "text":
        text = export_text(results, path=out)
    elif fmt == "dnsdist":
        text = export_dnsdist(results, path=out)
    elif fmt == "unbound":
        text = export_unbound(results, path=out)
    else:
        logger.error("Unknown export format: %s", fmt)
        return 1

    if not out:
        print(text, end="")
    else:
        logger.info("Wrote %s export to %s", fmt, out)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="resolver-inventory",
        description="Aggregate, validate, score, and export public DNS and DoH resolvers.",
    )
    parser.add_argument("--config", "-c", metavar="FILE", help="Path to YAML config file")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # discover
    p_discover = sub.add_parser("discover", help="Gather raw candidates from all sources")
    p_discover.add_argument("--output", "-o", metavar="FILE", help="Write candidates JSON here")

    # validate
    p_validate = sub.add_parser("validate", help="Run probes and emit scored records")
    p_validate.add_argument("--input", "-i", metavar="FILE", help="Pre-discovered candidates JSON")
    p_validate.add_argument("--output", "-o", metavar="FILE", help="Write validation results JSON")

    # refresh
    p_refresh = sub.add_parser("refresh", help="Full pipeline: discover → validate → export")
    p_refresh.add_argument("--output", "-o", metavar="DIR", help="Output directory")

    # export
    p_export = sub.add_parser("export", help="Render outputs from validated records")
    p_export.add_argument(
        "format",
        choices=["json", "text", "dnsdist", "unbound"],
        help="Output format",
    )
    p_export.add_argument("--input", "-i", metavar="FILE", help="Validated results JSON")
    p_export.add_argument("--output", "-o", metavar="FILE", help="Write output here")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    handlers = {
        "discover": cmd_discover,
        "validate": cmd_validate,
        "refresh": cmd_refresh,
        "export": cmd_export,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
