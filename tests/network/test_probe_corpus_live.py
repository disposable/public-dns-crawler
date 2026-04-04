"""Optional live probe corpus generation checks against public baseline resolvers."""

from __future__ import annotations

import os

import pytest

from resolver_inventory.probe_corpus.generator import generate_probe_corpus
from resolver_inventory.probe_corpus.sources import load_seed_snapshot
from resolver_inventory.settings import ProbeCorpusConfig

pytestmark = pytest.mark.network


@pytest.mark.skipif(
    os.environ.get("RUN_NETWORK_TESTS") != "1",
    reason="set RUN_NETWORK_TESTS=1 to enable live baseline checks",
)
def test_generate_probe_corpus_with_live_baselines() -> None:
    config = ProbeCorpusConfig()
    config.thresholds.min_positive_exact = 1
    config.thresholds.min_positive_consensus = 1
    config.thresholds.min_negative_generated = 1

    result = generate_probe_corpus(config, load_seed_snapshot())

    assert result.corpus.probes
