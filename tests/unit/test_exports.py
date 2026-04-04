"""Unit tests for exporters."""

from __future__ import annotations

from resolver_inventory.export.dnsdist import export_dnsdist
from resolver_inventory.export.json import export_filtered_json, export_json
from resolver_inventory.export.text import export_text
from resolver_inventory.export.unbound import export_unbound
from resolver_inventory.models import Candidate, FilteredCandidate, ProbeResult, ValidationResult


def _dns_result(
    host: str = "192.0.2.1",
    port: int = 53,
    accepted: bool = True,
    provider: str | None = "TestISP",
) -> ValidationResult:
    c = Candidate(
        provider=provider,
        source="test",
        transport="dns-udp",
        endpoint_url=None,
        host=host,
        port=port,
        path=None,
    )
    return ValidationResult(
        candidate=c,
        accepted=accepted,
        score=90,
        status="accepted" if accepted else "rejected",
        reasons=[],
        probes=[ProbeResult(ok=True, probe="x", latency_ms=5.0)],
    )


def _doh_result(
    url: str = "https://dns.example.com/dns-query",
    accepted: bool = True,
) -> ValidationResult:
    c = Candidate(
        provider="ExampleDoH",
        source="test",
        transport="doh",
        endpoint_url=url,
        host="dns.example.com",
        port=443,
        path="/dns-query",
        tls_server_name="dns.example.com",
    )
    return ValidationResult(
        candidate=c,
        accepted=accepted,
        score=95,
        status="accepted" if accepted else "rejected",
        reasons=[],
        probes=[ProbeResult(ok=True, probe="doh:positive:test", latency_ms=20.0)],
    )


class TestJsonExport:
    def test_accepted_only_default(self) -> None:
        results = [_dns_result(accepted=True), _dns_result("192.0.2.2", accepted=False)]
        text = export_json(results)
        import json

        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["candidate"]["host"] == "192.0.2.1"

    def test_all_results(self) -> None:
        results = [_dns_result(accepted=True), _dns_result("192.0.2.2", accepted=False)]
        text = export_json(results, accepted_only=False)
        import json

        data = json.loads(text)
        assert len(data) == 2

    def test_output_has_required_fields(self) -> None:
        import json

        text = export_json([_dns_result()])
        data = json.loads(text)
        record = data[0]
        assert "status" in record
        assert "score" in record
        assert "candidate" in record
        assert "probes" in record

    def test_compact_json_default(self) -> None:
        text = export_json([_dns_result()])
        assert "\n" not in text

    def test_status_filter(self) -> None:
        import json

        candidate = _dns_result(host="192.0.2.3", accepted=True)
        candidate.status = "candidate"
        candidate.accepted = False
        rejected = _dns_result(host="192.0.2.4", accepted=False)
        text = export_json([_dns_result(), candidate, rejected], statuses={"rejected"})
        data = json.loads(text)
        assert len(data) == 1
        assert data[0]["status"] == "rejected"

    def test_default_sort_order_is_stable(self) -> None:
        import json

        a = _dns_result(host="192.0.2.10", accepted=True)
        b = _dns_result(host="192.0.2.2", accepted=True)
        text = export_json([a, b])
        data = json.loads(text)
        assert [record["candidate"]["host"] for record in data] == ["192.0.2.10", "192.0.2.2"]

    def test_rejected_only_keeps_failed_probes(self) -> None:
        import json

        rejected = _dns_result(host="192.0.2.4", accepted=False)
        rejected.probes = [
            ProbeResult(ok=True, probe="p-ok", latency_ms=10.0),
            ProbeResult(ok=False, probe="p-fail-1", error="timeout"),
            ProbeResult(ok=False, probe="p-fail-2", error="answer_mismatch"),
        ]
        text = export_json([rejected], accepted_only=False, rejected_failed_only=True)
        data = json.loads(text)
        assert data[0]["all_probes_failed"] is False
        assert [probe["probe"] for probe in data[0]["probes"]] == ["p-fail-1", "p-fail-2"]

    def test_rejected_all_probes_failed_uses_flag_without_probe_payload(self) -> None:
        import json

        rejected = _dns_result(host="192.0.2.5", accepted=False)
        rejected.probes = [
            ProbeResult(ok=False, probe="p-fail-1", error="timeout"),
            ProbeResult(ok=False, probe="p-fail-2", error="answer_mismatch"),
        ]
        text = export_json([rejected], accepted_only=False, rejected_failed_only=True)
        data = json.loads(text)
        assert data[0]["all_probes_failed"] is True
        assert "probes" not in data[0]

    def test_split_json_output_into_parts(self, tmp_path: object) -> None:
        from pathlib import Path

        out = Path(str(tmp_path)) / "rejected.json"
        rejected = _dns_result(host="192.0.2.99", accepted=False)
        rejected.probes = [ProbeResult(ok=False, probe="probe", error="timeout")]
        export_json(
            [rejected, rejected, rejected, rejected],
            accepted_only=False,
            rejected_failed_only=True,
            path=out,
            max_file_bytes=150,
        )
        assert not out.exists()
        parts = sorted(out.parent.glob("rejected.part-*.json"))
        assert len(parts) >= 2

    def test_write_to_file(self, tmp_path: object) -> None:
        import json
        from pathlib import Path

        out = Path(str(tmp_path)) / "out.json"
        export_json([_dns_result()], path=out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert len(data) == 1

    def test_filtered_export_contains_reason_and_detail(self) -> None:
        import json

        record = FilteredCandidate(
            candidate=Candidate(
                provider="TestProvider",
                source="publicdns_info",
                transport="dns-udp",
                endpoint_url=None,
                host="192.0.2.1",
                port=53,
                path=None,
                metadata={"reliability": "0.20"},
            ),
            reason="source_reliability_below_min",
            detail="public-dns.info reliability 0.20 is below configured minimum 0.50",
            stage="source",
        )
        text = export_filtered_json([record])
        data = json.loads(text)
        assert data[0]["reason"] == "source_reliability_below_min"
        assert "configured minimum 0.50" in data[0]["detail"]
        assert data[0]["candidate"]["host"] == "192.0.2.1"


class TestTextExport:
    def test_basic_dns_output(self) -> None:
        text = export_text([_dns_result()])
        assert "192.0.2.1:53" in text

    def test_rejected_excluded_by_default(self) -> None:
        results = [_dns_result(accepted=True), _dns_result("10.0.0.1", accepted=False)]
        text = export_text(results)
        assert "10.0.0.1" not in text

    def test_doh_excluded_by_default(self) -> None:
        results = [_dns_result(), _doh_result()]
        text = export_text(results)
        assert "https://" not in text

    def test_doh_included_when_flag_set(self) -> None:
        results = [_dns_result(), _doh_result()]
        text = export_text(results, include_doh=True)
        assert "https://dns.example.com/dns-query" in text

    def test_deduplication(self) -> None:
        results = [_dns_result(), _dns_result()]
        lines = export_text(results).strip().splitlines()
        assert len(lines) == 1


class TestDnsdistExport:
    def test_dns_backend_present(self) -> None:
        text = export_dnsdist([_dns_result()])
        assert "newServer" in text
        assert "192.0.2.1:53" in text

    def test_doh_backend_present(self) -> None:
        text = export_dnsdist([_doh_result()])
        assert "dohPath" in text
        assert "subjectName" in text
        assert "dns.example.com" in text

    def test_header_present(self) -> None:
        text = export_dnsdist([_dns_result()])
        assert "resolver-inventory" in text

    def test_rejected_excluded(self) -> None:
        text = export_dnsdist([_dns_result(accepted=False)])
        assert "192.0.2.1" not in text

    def test_syntactically_correct_lua(self) -> None:
        text = export_dnsdist([_dns_result(), _doh_result()])
        assert text.count("newServer") == 2


class TestUnboundExport:
    def test_forward_zone_present(self) -> None:
        text = export_unbound([_dns_result()])
        assert "forward-zone:" in text
        assert "forward-addr:" in text
        assert "192.0.2.1" in text

    def test_doh_not_included(self) -> None:
        text = export_unbound([_doh_result()])
        assert "forward-addr:" not in text

    def test_deduplication(self) -> None:
        results = [_dns_result(), _dns_result()]
        text = export_unbound(results)
        assert text.count("forward-addr:") == 1

    def test_custom_forward_zone(self) -> None:
        text = export_unbound([_dns_result()], forward_zone="example.com.")
        assert '"example.com."' in text

    def test_rejected_excluded(self) -> None:
        text = export_unbound([_dns_result(accepted=False)])
        assert "192.0.2.1" not in text
