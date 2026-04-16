use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Canonical severity levels used throughout the ingest pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    /// Parse severity from a free-form string.  Case-insensitive.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "critical" | "crit" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" | "moderate" | "warning" => Self::Medium,
            "low" => Self::Low,
            "info" | "informational" | "note" => Self::Info,
            _ => Self::Unknown,
        }
    }

    /// Numeric CVSS-style weight for risk scoring.
    pub fn weight(self) -> f32 {
        match self {
            Self::Critical => 10.0,
            Self::High => 8.0,
            Self::Medium => 5.0,
            Self::Low => 3.0,
            Self::Info => 1.0,
            Self::Unknown => 0.0,
        }
    }
}

/// A fully normalised security finding ready for database insertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// UUID v4 assigned at normalisation time.
    pub id: Uuid,

    /// Originating scan identifier (from the CosmicSec platform).
    pub scan_id: String,

    /// Short human-readable vulnerability title.
    pub title: String,

    /// Detailed description of the vulnerability.
    pub description: String,

    /// Normalised severity level.
    pub severity: Severity,

    /// CVSS 3.x base score, if available.
    pub cvss_score: Option<f32>,

    /// Vulnerability category or OWASP classification.
    pub category: String,

    /// CVE identifier, if applicable.
    pub cve_id: Option<String>,

    /// Target host / IP address.
    pub host: String,

    /// Affected port, if applicable.
    pub port: Option<u16>,

    /// Protocol (tcp, udp, http, …).
    pub protocol: Option<String>,

    /// Remediation guidance.
    pub recommendation: String,

    /// Raw evidence snippet (truncated to 4 KB).
    pub raw_evidence: String,

    /// Timestamp of detection.
    pub detected_at: DateTime<Utc>,

    /// Additional parser-specific metadata.
    pub extra: serde_json::Value,
}

impl Finding {
    /// Create a new finding, assigning a fresh UUID and the current timestamp.
    pub fn new(scan_id: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            scan_id: scan_id.into(),
            title: title.into(),
            description: String::new(),
            severity: Severity::Unknown,
            cvss_score: None,
            category: String::new(),
            cve_id: None,
            host: String::new(),
            port: None,
            protocol: None,
            recommendation: String::new(),
            raw_evidence: String::new(),
            detected_at: Utc::now(),
            extra: serde_json::Value::Null,
        }
    }

    /// Truncate `raw_evidence` to at most `max_bytes` UTF-8 bytes.
    pub fn truncate_evidence(&mut self, max_bytes: usize) {
        if self.raw_evidence.len() > max_bytes {
            // Safe truncation at UTF-8 char boundary
            let mut end = max_bytes;
            while !self.raw_evidence.is_char_boundary(end) {
                end -= 1;
            }
            self.raw_evidence.truncate(end);
        }
    }
}
