"""Backward-compatible import path for probe corpus schema helpers."""

from resolver_inventory.probe_corpus.schema import (
    ProbeCorpus,
    ProbeDefinition,
    parse_probe_corpus,
)
from resolver_inventory.probe_corpus.schema import (
    ProbeSchemaError as CorpusSchemaError,
)

__all__ = ["CorpusSchemaError", "ProbeCorpus", "ProbeDefinition", "parse_probe_corpus"]
