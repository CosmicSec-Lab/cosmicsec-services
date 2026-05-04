use crate::normalizer::Finding;
use anyhow::Result;

/// Trait that every parser must implement.
pub trait Parser: Send + Sync {
    /// Parse raw bytes into a list of normalised findings.
    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>>;

    /// Human-readable name for logging.
    fn name(&self) -> &'static str;
}

pub mod generic;
pub mod grype;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod semgrep;
pub mod trivy;
pub mod zap;

pub use generic::GenericJsonParser;
pub use grype::GrypeParser;
pub use nikto::NiktoParser;
pub use nmap::NmapParser;
pub use nuclei::NucleiParser;
pub use semgrep::SemgrepParser;
pub use trivy::TrivyParser;
pub use zap::ZapParser;

/// Select the appropriate parser based on a tool name string.
pub fn parser_for_tool(tool: &str) -> Box<dyn Parser> {
    match tool.to_lowercase().as_str() {
        "nmap" => Box::new(NmapParser),
        "nuclei" => Box::new(NucleiParser),
        "nikto" => Box::new(NiktoParser),
        "zap" | "owasp-zap" => Box::new(ZapParser),
        "semgrep" => Box::new(SemgrepParser),
        "trivy" => Box::new(TrivyParser),
        "grype" => Box::new(GrypeParser),
        _ => Box::new(GenericJsonParser),
    }
}
