/// Core data schema for ingest findings.
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Default for SeverityLevel {
    fn default() -> Self {
        SeverityLevel::Info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier (UUID v4).
    pub id: String,
    pub title: String,
    pub severity: SeverityLevel,
    pub description: String,
    pub evidence: String,
    pub tool: String,
    pub target: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

impl Finding {
    pub fn new(
        title: impl Into<String>,
        severity: SeverityLevel,
        description: impl Into<String>,
        evidence: impl Into<String>,
        tool: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Finding {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            severity,
            description: description.into(),
            evidence: evidence.into(),
            tool: tool.into(),
            target: target.into(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IngestResult {
    pub findings: Vec<Finding>,
    pub tool: String,
    pub target: String,
    pub duration_ms: f64,
}

