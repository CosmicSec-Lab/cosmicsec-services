use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use chrono::Utc;

/// Parser for Grype JSON output (`grype -o json`).
pub struct GrypeParser;

impl super::Parser for GrypeParser {
    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let report: GrypeReport = serde_json::from_slice(raw)?;
        let mut findings = Vec::new();

        for m in report.matches {
            let vuln = m.vulnerability;
            let mut f = Finding::new(
                scan_id,
                &format!("{}: {}@{}", vuln.id, m.artifact.name, m.artifact.version),
            );
            f.severity = Severity::from_str(&vuln.severity);
            f.description = vuln.description;
            f.category = "vulnerability".to_string();
            f.cve_id = Some(vuln.id);
            f.cvss_score = vuln.cvss.first().and_then(|c| {
                c.metrics.as_ref().and_then(|m| {
                    if m.base_score > 0.0 {
                        Some(m.base_score as f32)
                    } else {
                        None
                    }
                })
            });
            f.recommendation = vuln
                .fix
                .fix_versions
                .map(|v| format!("Upgrade to {}", v))
                .unwrap_or_default();
            f.host = m.artifact.name.clone();
            f.raw_evidence = format!(
                "Artifact: {}@{}\nType: {}",
                m.artifact.name, m.artifact.version, m.artifact.type_
            );
            f.truncate_evidence(4096);
            f.detected_at = Utc::now();
            findings.push(f);
        }

        Ok(findings)
    }

    fn name(&self) -> &'static str {
        "grype"
    }
}

#[derive(serde::Deserialize)]
struct GrypeReport {
    #[serde(default)]
    matches: Vec<GrypeMatch>,
}

#[derive(serde::Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVuln,
    artifact: GrypeArtifact,
}

#[derive(serde::Deserialize)]
struct GrypeVuln {
    #[serde(default)]
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    fix: GrypeFix,
    #[serde(default)]
    cvss: Vec<GrypeCVSS>,
}

#[derive(serde::Deserialize, Default)]
struct GrypeFix {
    #[serde(default)]
    versions: Option<String>,
    #[serde(default)]
    fix_versions: Option<String>,
}

#[derive(serde::Deserialize)]
struct GrypeArtifact {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: String,
    #[serde(default, rename = "type")]
    type_: String,
}

#[derive(serde::Deserialize)]
struct GrypeCVSS {
    #[serde(default)]
    metrics: Option<GrypeMetrics>,
}

#[derive(serde::Deserialize)]
struct GrypeMetrics {
    #[serde(default)]
    base_score: f64,
}
