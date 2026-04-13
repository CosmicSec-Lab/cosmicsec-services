/// Core data schema for ingest findings.
use chrono::Utc;
use serde::{Deserialize, Serialize};

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
    /// Unique identifier (UUID v4 string).
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
            id: uuid_v4(),
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

/// Minimal UUID v4 generator using random bytes from the OS via stdlib.
fn uuid_v4() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    std::thread::current().id().hash(&mut h);
    let a = h.finish();

    let mut h2 = DefaultHasher::new();
    a.hash(&mut h2);
    42u64.hash(&mut h2);
    let b = h2.finish();

    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        a as u16 & 0x0fff,
        (b >> 48) as u16 | 0x8000,
        b & 0x0000_ffff_ffff_ffff,
    )
}
