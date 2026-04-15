use super::Parser;
use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use serde::Deserialize;

/// OWASP Nikto parser (JSON output via `-Format json`).
pub struct NiktoParser;

#[derive(Debug, Deserialize)]
struct NiktoReport {
    #[serde(default)]
    vulnerabilities: Vec<NiktoVuln>,

    #[serde(default)]
    host: String,

    #[serde(default)]
    port: String,
}

#[derive(Debug, Deserialize)]
struct NiktoVuln {
    #[serde(rename = "id", default)]
    id: String,

    #[serde(rename = "method", default)]
    method: String,

    #[serde(rename = "description", default)]
    description: String,

    #[serde(rename = "url", default)]
    url: String,

    #[serde(rename = "references", default)]
    references: Vec<String>,
}

impl Parser for NiktoParser {
    fn name(&self) -> &'static str {
        "nikto"
    }

    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let report: NiktoReport = serde_json::from_slice(raw)
            .map_err(|e| anyhow::anyhow!("nikto JSON parse error: {e}"))?;

        let host = report.host.clone();
        let port = report.port.parse::<u16>().ok();

        let findings = report
            .vulnerabilities
            .into_iter()
            .map(|v| {
                let title = if v.description.len() > 80 {
                    format!("{}…", &v.description[..77])
                } else {
                    v.description.clone()
                };
                let mut f = Finding::new(scan_id, title);
                f.host = host.clone();
                f.port = port;
                f.protocol = Some("http".to_owned());
                f.description = v.description.clone();
                f.raw_evidence = format!("{} {} — refs: {}", v.method, v.url, v.references.join(", "));
                f.category = format!("web/nikto/{}", v.id);
                f.severity = severity_from_nikto_id(&v.id);
                f.recommendation = "Review the identified web server misconfiguration and apply \
                                     the appropriate vendor patch or hardening guidance."
                    .to_owned();
                f.truncate_evidence(4096);
                f
            })
            .collect();

        Ok(findings)
    }
}

fn severity_from_nikto_id(id: &str) -> Severity {
    // Nikto OSVDB IDs loosely map to severity.  Default to Medium as a
    // conservative choice; callers can re-score using CVSS if needed.
    let _ = id;
    Severity::Medium
}
