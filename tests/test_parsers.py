"""Tests for the ingest parser modules."""

import pytest

from ingest.normalizer import normalize_finding


class TestNormalizeFinding:
    def test_normalize_minimal(self):
        finding = {
            "title": "Test Finding",
            "severity": "high",
            "description": "Test description",
            "host": "example.com",
            "category": "vulnerability",
        }
        result = normalize_finding(finding, tool="test_tool", scan_id="scan-123")
        assert result["title"] == "Test Finding"
        assert result["severity"] == "high"
        assert result["scan_id"] == "scan-123"
        assert "id" in result
        assert "detected_at" in result

    def test_normalize_severity_mapping(self):
        finding = {
            "title": "Test",
            "severity": "CRITICAL",
            "host": "example.com",
            "category": "vuln",
        }
        result = normalize_finding(finding, tool="test", scan_id="scan-1")
        assert result["severity"] in {"critical", "high", "medium", "low", "info"}

    def test_normalize_sets_defaults(self):
        finding = {
            "title": "Test",
            "severity": "high",
            "host": "example.com",
            "category": "vuln",
        }
        result = normalize_finding(finding, tool="test", scan_id="scan-1")
        assert result.get("description") is not None
        assert result.get("recommendation") is not None


class TestNmapParser:
    def test_parse_open_ports(self, sample_nmap_xml):
        from ingest.parsers.nmap import parse_nmap_xml
        findings = parse_nmap_xml(sample_nmap_xml, scan_id="scan-1")
        assert len(findings) >= 2
        hosts = [f["host"] for f in findings]
        assert "example.com" in hosts or "93.184.216.34" in hosts

    def test_parse_detects_services(self, sample_nmap_xml):
        from ingest.parsers.nmap import parse_nmap_xml
        findings = parse_nmap_xml(sample_nmap_xml, scan_id="scan-1")
        services = [f.get("extra", {}).get("service", "") for f in findings]
        assert "ssh" in services or "http" in services

    def test_parse_empty_xml(self):
        from ingest.parsers.nmap import parse_nmap_xml
        findings = parse_nmap_xml("<?xml version='1.0'?><nmaprun></nmaprun>", scan_id="scan-1")
        assert len(findings) == 0


class TestNucleiParser:
    def test_parse_jsonl(self, sample_nuclei_jsonl):
        from ingest.parsers.nuclei import parse_nuclei_jsonl
        findings = parse_nuclei_jsonl(sample_nuclei_jsonl, scan_id="scan-1")
        assert len(findings) == 1
        assert findings[0]["tool"] == "nuclei"

    def test_parse_empty(self):
        from ingest.parsers.nuclei import parse_nuclei_jsonl
        findings = parse_nuclei_jsonl("", scan_id="scan-1")
        assert len(findings) == 0


class TestGrypeParser:
    def test_parse_vulnerabilities(self, sample_grype_json):
        from ingest.parsers.grype import parse_grype_json
        findings = parse_grype_json(sample_grype_json, scan_id="scan-1")
        assert len(findings) == 1
        assert findings[0]["tool"] == "grype"

    def test_parse_empty(self):
        from ingest.parsers.grype import parse_grype_json
        findings = parse_grype_json({"matches": []}, scan_id="scan-1")
        assert len(findings) == 0


class TestTrivyParser:
    def test_parse_results(self, sample_trivy_json):
        from ingest.parsers.trivy import parse_trivy_json
        findings = parse_trivy_json(sample_trivy_json, scan_id="scan-1")
        assert len(findings) == 1
        assert findings[0]["tool"] == "trivy"

    def test_parse_empty(self):
        from ingest.parsers.trivy import parse_trivy_json
        findings = parse_trivy_json({"Results": []}, scan_id="scan-1")
        assert len(findings) == 0


class TestSemgrepParser:
    def test_parse_results(self, sample_semgrep_json):
        from ingest.parsers.semgrep import parse_semgrep_json
        findings = parse_semgrep_json(sample_semgrep_json, scan_id="scan-1")
        assert len(findings) == 1
        assert findings[0]["tool"] == "semgrep"

    def test_parse_empty(self):
        from ingest.parsers.semgrep import parse_semgrep_json
        findings = parse_semgrep_json({"results": []}, scan_id="scan-1")
        assert len(findings) == 0


class TestGenericParser:
    def test_parse_generic_json(self):
        from ingest.parsers.generic import parse_generic_json
        data = {
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "severity": "HIGH", "description": "Test vuln"}
            ]
        }
        findings = parse_generic_json(data, scan_id="scan-1", tool="generic")
        assert len(findings) == 1

    def test_parse_generic_json_no_vulns(self):
        from ingest.parsers.generic import parse_generic_json
        findings = parse_generic_json({}, scan_id="scan-1", tool="generic")
        assert len(findings) == 0
