"""Source adapters for the paulmillr/encrypted-dns resolver profile repository.

The project publishes signed Apple encrypted-DNS profiles; its machine-readable
source is one JSON file per provider under ``src/``. Each profile declares
``variants`` carrying ``https.ServerURLOrName`` (a DoH URL), ``tls.
ServerURLOrName`` (a DoT target), and plain ``ServerAddresses`` IP literals -
which also serve as bootstrap addresses for the TLS endpoints. The file list is
resolved through the GitHub contents API and each profile's ``download_url`` is
fetched; ``hidden`` template profiles are ignored.
"""

from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlparse

from resolver_inventory.models import Candidate
from resolver_inventory.sources.base import BaseSource
from resolver_inventory.util.logging import get_logger
from resolver_inventory.util.retry import fetch_url

logger = get_logger(__name__)

PAULMILLR_LISTING_URL = "https://api.github.com/repos/paulmillr/encrypted-dns/contents/src"

DEFAULT_DOT_PORT = 853


class _ProfileError(ValueError):
    """A single profile file is malformed; the source must keep going."""


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _split_addresses(values: object) -> tuple[list[str], list[str]]:
    """Classify ``ServerAddresses`` literals into (ipv4, ipv6) lists."""
    v4: list[str] = []
    v6: list[str] = []
    if not isinstance(values, list):
        return v4, v6
    for raw in values:
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        (v4 if addr.version == 4 else v6).append(str(addr))
    return v4, v6


def _split_tls_target(text: str) -> tuple[str, int]:
    """Split a ``host[:port]`` / ``[v6][:port]`` DoT target field."""
    text = text.strip()
    if not text:
        return "", 0
    try:
        if text.startswith("["):
            close = text.find("]")
            if close < 0:
                return "", 0
            host = text[1:close]
            rest = text[close + 1 :]
            port = int(rest[1:]) if rest.startswith(":") else DEFAULT_DOT_PORT
            return host, port
        if text.count(":") == 1:
            host, _, port_text = text.partition(":")
            port = int(port_text) if port_text else DEFAULT_DOT_PORT
            return host, port
        # Bare hostname or unbracketed IPv6 literal.
        return text, DEFAULT_DOT_PORT
    except ValueError:
        return "", 0


def _parse_doh_url(url: str) -> tuple[str, int, str]:
    """Extract (host, port, path); returns ("", 0, "") for malformed URLs."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
    except ValueError:
        return "", 0, ""
    return host, port, parsed.path or "/dns-query"


class _PaulMillrSource(BaseSource):
    """Fetch the profile listing and yield candidates of one family."""

    SOURCE_NAME = "paulmillr"

    def _variants(self) -> list[tuple[str, str, dict[str, object]]]:
        """Return (provider_label, variant_key, variant) tuples."""
        listing_url = self.entry.url or self.entry.extra.get("url") or PAULMILLR_LISTING_URL
        try:
            listing = json.loads(
                fetch_url(listing_url, timeout=30).decode("utf-8", errors="replace")
            )
        except Exception as exc:
            logger.warning("paulmillr listing fetch failed: %s", exc)
            return []
        if not isinstance(listing, list):
            logger.warning("paulmillr: unexpected listing payload")
            return []

        names = sorted(
            _text(item.get("name"))
            for item in listing
            if isinstance(item, dict) and _text(item.get("name")).endswith(".json")
        )
        downloads = {
            _text(item.get("name")): _text(item.get("download_url"))
            for item in listing
            if isinstance(item, dict)
        }

        out: list[tuple[str, str, dict[str, object]]] = []
        for name in names:
            download_url = downloads.get(name)
            if not download_url:
                continue
            try:
                profile = json.loads(
                    fetch_url(download_url, timeout=30).decode("utf-8", errors="replace")
                )
            except Exception as exc:
                logger.warning("paulmillr: skipping %s: %s", name, exc)
                continue
            if not isinstance(profile, dict) or profile.get("hidden"):
                continue
            names_map = profile.get("names")
            base = (
                _text(names_map.get("en")) if isinstance(names_map, dict) else ""
            ) or name.removesuffix(".json")
            variants = profile.get("variants")
            if not isinstance(variants, dict):
                continue
            single = len(variants) == 1
            for variant_key in sorted(variants):
                variant = variants[variant_key]
                if not isinstance(variant, dict):
                    continue
                vnames = variant.get("names")
                variant_label = (
                    _text(vnames.get("en")) if isinstance(vnames, dict) else ""
                ) or variant_key
                provider = base if single else f"{base}: {variant_label}"
                out.append((provider, variant_key, variant))
        return out

    def _candidates_for(
        self, provider: str, variant_key: str, variant: dict[str, object]
    ) -> list[Candidate]:
        raise NotImplementedError

    def _metadata(self, variant_key: str, variant: dict[str, object]) -> dict[str, str]:
        metadata = {"variant": variant_key}
        for key in ("region", "censorship"):
            value = variant.get(key)
            if value is not None:
                metadata[key] = str(value).lower() if isinstance(value, bool) else str(value)
        return metadata

    def candidates(self) -> list[Candidate]:
        variants = self._variants()
        results: list[Candidate] = []
        seen: set[tuple] = set()
        for provider, variant_key, variant in variants:
            for candidate in self._candidates_for(provider, variant_key, variant):
                key = self._dedup_key(candidate)
                if key in seen:
                    continue
                seen.add(key)
                results.append(candidate)
        logger.info("paulmillr: found %d candidates", len(results))
        return results

    def _dedup_key(self, candidate: Candidate) -> tuple:
        return (
            candidate.transport,
            candidate.host,
            candidate.port,
            candidate.path or "",
            candidate.tls_server_name or "",
        )


class PaulMillrDnsSource(_PaulMillrSource):
    """Plain-DNS candidates from profile ``ServerAddresses``."""

    def _candidates_for(
        self, provider: str, variant_key: str, variant: dict[str, object]
    ) -> list[Candidate]:
        v4, v6 = _split_addresses(variant.get("ServerAddresses"))
        return [
            Candidate(
                provider=provider,
                source=self.SOURCE_NAME,
                transport=transport,  # type: ignore[arg-type]
                endpoint_url=None,
                host=addr,
                port=53,
                path=None,
                metadata=self._metadata(variant_key, variant),
            )
            for addr in v4 + v6
            for transport in ("dns-udp", "dns-tcp")
        ]

    def _dedup_key(self, candidate: Candidate) -> tuple:
        return (candidate.transport, candidate.host)


class PaulMillrDohSource(_PaulMillrSource):
    """DoH candidates from variant ``https.ServerURLOrName`` fields."""

    def _candidates_for(
        self, provider: str, variant_key: str, variant: dict[str, object]
    ) -> list[Candidate]:
        https = variant.get("https")
        url = _text(https.get("ServerURLOrName")) if isinstance(https, dict) else ""
        url = url.strip()
        if not url.startswith("https://"):
            return []
        host, port, path = _parse_doh_url(url)
        if not host:
            return []
        v4, v6 = _split_addresses(variant.get("ServerAddresses"))
        return [
            Candidate(
                provider=provider,
                source=self.SOURCE_NAME,
                transport="doh",
                endpoint_url=url,
                host=host,
                port=port,
                path=path,
                bootstrap_ipv4=v4,
                bootstrap_ipv6=v6,
                tls_server_name=host,
                metadata=self._metadata(variant_key, variant),
            )
        ]


class PaulMillrDotSource(_PaulMillrSource):
    """DoT candidates from variant ``tls.ServerURLOrName`` fields."""

    def _candidates_for(
        self, provider: str, variant_key: str, variant: dict[str, object]
    ) -> list[Candidate]:
        tls = variant.get("tls")
        target = _text(tls.get("ServerURLOrName")) if isinstance(tls, dict) else ""
        host, port = _split_tls_target(target)
        if not host:
            return []
        v4, v6 = _split_addresses(variant.get("ServerAddresses"))
        return [
            Candidate(
                provider=provider,
                source=self.SOURCE_NAME,
                transport="dot",
                endpoint_url=None,
                host=host,
                port=port,
                path=None,
                bootstrap_ipv4=v4,
                bootstrap_ipv6=v6,
                tls_server_name=host,
                metadata=self._metadata(variant_key, variant),
            )
        ]
