/// Parse errors for all ingest parsers.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("XML parse error: {0}")]
    Xml(#[from] xml::reader::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    Other(String),
}
