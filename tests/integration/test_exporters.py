"""Integration tests verifying exporter output against fixture-validated records."""

from __future__ import annotations

import asyncio
import json

import pytest

from resolver_inventory.export.dnsdist import export_dnsdist
from resolver_inventory.export.json import export_json
from resolver_inventory.export.text import export_text
from resolver_inventory.models import Candidate
from resolver_inventory.settings import Settings
from resolver_inventory.validate.corpus import build_corpus
from resolver_inventory.validate.dns_plain import validate_dns_candidate
from resolver_inventory.validate.scorer import score
from tests.fixtures.dns_authority import ZONE_NAME, AuthoritativeDnsFixture

pytestmark = pytest.mark.integration

CONTROLLED_ZONE = ZONE_NAME.rstrip(".")


def _make_settings() -> Settings:
    s = Settings()
    s.validation.corpus.mode = "controlled"
    s.validation.corpus.zone = CONTROLLED_ZONE
    s.validation.rounds = 1
    s.validation.timeout_ms = 2000
    return s


def _get_accepted_result() -> object:
    with AuthoritativeDnsFixture() as fix:
        candidate = Candidate(
            provider="FixtureProvider",
            source="integration-test",
            transport="dns-udp",
            endpoint_url=None,
            host=fix.host,
            port=fix.port,
            path=None,
        )
        settings = _make_settings()
        corpus = build_corpus(settings.validation.corpus)
        probes = asyncio.run(validate_dns_candidate(candidate, corpus, timeout_s=2.0, rounds=1))
        return score(candidate, probes, settings)


class TestExportersWithFixtureResult:
    def setup_method(self) -> None:
        self.result = _get_accepted_result()

    def test_json_exporter_syntactically_correct(self) -> None:
        from resolver_inventory.models import ValidationResult

        assert isinstance(self.result, ValidationResult)
        text = export_json([self.result], accepted_only=False)
        parsed = json.loads(text)
        assert isinstance(parsed, list)
        assert len(parsed) == 1
        assert "candidate" in parsed[0]
        assert "score" in parsed[0]
        assert "probes" in parsed[0]

    def test_text_exporter_contains_host(self) -> None:
        from resolver_inventory.models import ValidationResult

        assert isinstance(self.result, ValidationResult)
        text = export_text([self.result])
        assert "127.0.0.1" in text

    def test_dnsdist_exporter_syntactically_correct(self) -> None:
        from resolver_inventory.models import ValidationResult

        assert isinstance(self.result, ValidationResult)
        text = export_dnsdist([self.result])
        assert "newServer" in text
        assert "127.0.0.1" in text
