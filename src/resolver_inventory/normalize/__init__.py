"""Normalization helpers for candidate deduplication and cleanup."""

from resolver_inventory.normalize.dns import normalize_dns_candidates
from resolver_inventory.normalize.doh import normalize_doh_candidates

__all__ = ["normalize_dns_candidates", "normalize_doh_candidates"]
