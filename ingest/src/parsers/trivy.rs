use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use chrono::Utc;

/// Parser for Trivy JSON output (`trivy image -f json`).
pub struct TrivyParser;

impl super::Parser for TrivyParser {
    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let report: TrivyReport = serde_json::from_slice(raw)?;
        let mut findings = Vec::new();

        for result in &report.results {
            if let Some(vulns) = &result.vulnerabilities {
                for v in vulns {
                    let mut f = Finding::new(scan_id, &v.vulnerability_id);
                    f.severity = Severity::from_str(&v.severity);
                    f.description = v.description.clone().unwrap_or_default();
                    f.category = "vulnerability".to_string();
                    f.cve_id = Some(v.vulnerability_id.clone());
                    f.cvss_score = v.cvss.and_then(|c| {
                        if c > 0.0 {
                            Some(c as f32)
                        } else {
                            None
                        }
                    });
                    f.recommendation = format!("Upgrade {} to fixed version", v.pkg_name);
                    f.host = result.target.clone();
                    f.raw_evidence = format!("Package: {}\nVersion: {}", v.pkg_name, v.installed_version);
                    f.truncate_evidence(4096);
                    f.detected_at = Utc::now();
                    findings.push(f);
                }
            }
            if let Some(misconfigs) = &result.misconfigurations {
                for m in misconfigs {
                    let mut f = Finding::new(scan_id, &m.id);
                    f.severity = Severity::from_str(&m.severity);
                    f.description = m.description.clone().unwrap_or_default();
                    f.category = "misconfiguration".to_string();
                    f.recommendation = m.resolution.clone().unwrap_or_default();
                    f.host = result.target.clone();
                    f.raw_evidence = format!("Type: {}\nQuery: {}", m.type_, m.query);
                    f.truncate_evidence(4096);
                    f.detected_at = Utc::now();
                    findings.push(f);
                }
            }
            if let Some(secrets) = &result.secrets {
                for s in secrets {
                    let mut f = Finding::new(scan_id, &s.title);
                    f.severity = Severity::from_str(&s.severity);
                    f.description = format!("Rule: {}", s.rule_id);
                    f.category = "secret".to_string();
                    f.recommendation = "Remove hardcoded secret from image".to_string();
                    f.host = result.target.clone();
                    f.raw_evidence = format!("RuleID: {}\nLine: {}", s.rule_id, s.start_line);
                    f.truncate_evidence(4096);
                    f.detected_at = Utc::now();
                    findings.push(f);
                }
            }
        }

        Ok(findings)
    }

    fn name(&self) -> &'static str {
        "trivy"
    }
}

#[derive(serde::Deserialize)]
struct TrivyReport {
    #[serde(default)]
    results: Vec<TrivyResult>,
}

#[derive(serde::Deserialize)]
struct TrivyResult {
    #[serde(default)]
    target: String,
    #[serde(default)]
    vulnerabilities: Option<Vec<TrivyVuln>>,
    #[serde(default)]
    misconfigurations: Option<Vec<TrivyMisconfig>>,
    #[serde(default)]
    secrets: Option<Vec<TrivySecret>>,
}

#[derive(serde::Deserialize)]
struct TrivyVuln {
    #[serde(default)]
    vulnerability_id: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    pkg_name: String,
    #[serde(default)]
    installed_version: String,
    #[serde(default)]
    cvss: Option<f64>,
}

#[derive(serde::Deserialize)]
struct TrivyMisconfig {
    #[serde(default)]
    id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    resolution: Option<String>,
    #[serde(rename = "Type", default)]
    type_: String,
    #[serde(default)]
    query: String,
}

#[derive(serde::Deserialize)]
struct TrivySecret {
    #[serde(default)]
    title: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    start_line: u64,
}
