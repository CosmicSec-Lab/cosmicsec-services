/// Integration tests for the CosmicSec ingest parsers.
///
/// These tests verify that each parser produces the expected number of findings
/// from the fixture files in `tests/fixtures/`.  No database or Redis connection
/// is required — they test the parsing logic only.
#[cfg(test)]
mod tests {
    use cosmicsec_ingest::parsers::{parser_for_tool, Parser};
    use cosmicsec_ingest::normalizer::Severity;

    const SCAN_ID: &str = "test-scan-001";

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!(
            "{}/tests/fixtures/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        std::fs::read(&path).unwrap_or_else(|e| panic!("Cannot read fixture {path}: {e}"))
    }

    #[test]
    fn nmap_parser_produces_open_port_findings() {
        let parser = parser_for_tool("nmap");
        let raw = fixture("sample_nmap.xml");
        let findings = parser.parse(SCAN_ID, &raw).expect("nmap parse failed");

        // Should find open ports: 22 and 443 (8080 is closed)
        let open_port_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category.contains("open-port"))
            .collect();
        assert!(
            open_port_findings.len() >= 2,
            "Expected ≥ 2 open-port findings, got {}: {:?}",
            open_port_findings.len(),
            open_port_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[test]
    fn nmap_parser_script_output_creates_finding() {
        let parser = parser_for_tool("nmap");
        let raw = fixture("sample_nmap.xml");
        let findings = parser.parse(SCAN_ID, &raw).expect("nmap parse failed");

        let script_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("ssl-weak-cipher"))
            .collect();
        assert!(
            !script_findings.is_empty(),
            "Expected ssl-weak-cipher finding but none found"
        );
        assert_eq!(
            script_findings[0].severity,
            Severity::Medium,
            "ssl-weak-cipher should be Medium"
        );
    }

    #[test]
    fn nmap_parser_all_findings_have_scan_id() {
        let parser = parser_for_tool("nmap");
        let raw = fixture("sample_nmap.xml");
        let findings = parser.parse(SCAN_ID, &raw).expect("nmap parse failed");

        for f in &findings {
            assert_eq!(f.scan_id, SCAN_ID);
        }
    }

    #[test]
    fn nuclei_parser_parses_jsonl() {
        let parser = parser_for_tool("nuclei");
        let raw = fixture("sample_nuclei.jsonl");
        let findings = parser.parse(SCAN_ID, &raw).expect("nuclei parse failed");

        assert_eq!(findings.len(), 3, "Expected 3 findings from sample_nuclei.jsonl");
    }

    #[test]
    fn nuclei_parser_critical_finding() {
        let parser = parser_for_tool("nuclei");
        let raw = fixture("sample_nuclei.jsonl");
        let findings = parser.parse(SCAN_ID, &raw).expect("nuclei parse failed");

        let log4shell = findings.iter().find(|f| f.title.contains("Log4Shell"));
        assert!(log4shell.is_some(), "Expected Log4Shell finding");
        let f = log4shell.unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.cve_id.as_deref(), Some("CVE-2021-44228"));
        assert_eq!(f.cvss_score, Some(10.0));
    }

    #[test]
    fn nuclei_parser_evidence_truncated_at_4096() {
        let parser = parser_for_tool("nuclei");
        let raw = fixture("sample_nuclei.jsonl");
        let findings = parser.parse(SCAN_ID, &raw).expect("nuclei parse failed");

        for f in &findings {
            assert!(
                f.raw_evidence.len() <= 4096,
                "raw_evidence exceeds 4096 bytes: {}",
                f.raw_evidence.len()
            );
        }
    }

    #[test]
    fn generic_json_parser_handles_array() {
        let raw = br#"[
            {"title": "SQLi", "severity": "high", "host": "db.example.com", "description": "SQL injection"},
            {"title": "XSS", "severity": "medium", "host": "web.example.com"}
        ]"#;
        let parser = parser_for_tool("unknown-tool");
        let findings = parser.parse(SCAN_ID, raw).expect("generic parse failed");
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].host, "db.example.com");
    }

    #[test]
    fn generic_json_parser_handles_single_object() {
        let raw = br#"{"title": "Hardcoded Secret", "severity": "critical", "host": "ci.example.com"}"#;
        let parser = parser_for_tool("generic_json");
        let findings = parser.parse(SCAN_ID, raw).expect("generic single object parse failed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
