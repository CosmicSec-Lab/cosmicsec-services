use super::Parser;
use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// OWASP ZAP XML report parser (`-format xml`).
pub struct ZapParser;

impl Parser for ZapParser {
    fn name(&self) -> &'static str {
        "zap"
    }

    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut reader = Reader::from_reader(raw);
        reader.config_mut().trim_text(true);

        let mut in_alert = false;
        let mut current: Option<Finding> = None;

        // Tracked field for the currently open element
        let mut current_tag = String::new();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => {
                    let tag = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_lowercase();
                    match tag.as_str() {
                        "alertitem" => {
                            in_alert = true;
                            current = Some(Finding::new(scan_id, "ZAP Finding"));
                        }
                        _ if in_alert => {
                            current_tag = tag;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Text(ref e)) if in_alert => {
                    let text = e.unescape().unwrap_or_default().trim().to_string();
                    if text.is_empty() {
                        continue;
                    }
                    if let Some(ref mut f) = current {
                        match current_tag.as_str() {
                            "alert" | "name" => f.title = text,
                            "riskdesc" => f.severity = severity_from_zap_risk(&text),
                            "desc" => f.description = text,
                            "solution" | "remedy" => f.recommendation = text,
                            "uri" | "url" => {
                                if f.host.is_empty() {
                                    f.host = text.clone();
                                }
                                f.raw_evidence = format!("url: {text}");
                            }
                            "cweid" => {
                                f.category = format!("CWE-{text}");
                            }
                            "evidence" => {
                                f.raw_evidence = text;
                            }
                            _ => {}
                        }
                    }
                }
                Ok(Event::End(ref e)) => {
                    let tag = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_lowercase();
                    if tag == "alertitem" {
                        if let Some(mut f) = current.take() {
                            f.truncate_evidence(4096);
                            findings.push(f);
                        }
                        in_alert = false;
                        current_tag.clear();
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("ZAP XML parse error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Ok(findings)
    }
}

fn severity_from_zap_risk(risk: &str) -> Severity {
    let lower = risk.to_lowercase();
    if lower.starts_with("high") {
        Severity::High
    } else if lower.starts_with("medium") {
        Severity::Medium
    } else if lower.starts_with("low") {
        Severity::Low
    } else if lower.starts_with("informational") || lower.starts_with("info") {
        Severity::Info
    } else {
        Severity::Unknown
    }
}
