use super::Parser;
use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Streaming Nmap XML parser.
///
/// Converts nmap's native XML format (`-oX`) into normalised `Finding` records.
/// Uses quick-xml in SAX mode to avoid loading the entire XML DOM into memory,
/// making it suitable for very large nmap output files (millions of hosts).
pub struct NmapParser;

impl Parser for NmapParser {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut reader = Reader::from_reader(raw);
        reader.config_mut().trim_text(true);

        let mut current_host = String::new();
        let mut current_port: u16 = 0;
        let mut current_proto = String::new();
        let mut current_service = String::new();
        let mut current_state = String::new();

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                    let tag = std::str::from_utf8(e.name().as_ref()).unwrap_or("").to_lowercase();

                    match tag.as_str() {
                        "address" => {
                            let addrtype = attr_value(e, b"addrtype").unwrap_or_default();
                            if addrtype == "ipv4" || addrtype == "ipv6" {
                                current_host =
                                    attr_value(e, b"addr").unwrap_or_default().to_owned();
                            }
                        }
                        "port" => {
                            current_proto = attr_value(e, b"protocol")
                                .unwrap_or("tcp")
                                .to_owned();
                            let port_str = attr_value(e, b"portid").unwrap_or("0");
                            current_port = port_str.parse().unwrap_or(0);
                        }
                        "state" => {
                            current_state = attr_value(e, b"state").unwrap_or("").to_owned();
                        }
                        "service" => {
                            current_service = attr_value(e, b"name").unwrap_or("").to_owned();
                        }
                        "script" => {
                            // Script output carries vulnerability information
                            let script_id = attr_value(e, b"id").unwrap_or("").to_owned();
                            let output = attr_value(e, b"output").unwrap_or("").to_owned();

                            if !output.is_empty() && !current_host.is_empty() {
                                let mut f =
                                    Finding::new(scan_id, format!("Nmap Script: {script_id}"));
                                f.host = current_host.clone();
                                f.port = Some(current_port);
                                f.protocol = Some(current_proto.clone());
                                f.description = output.clone();
                                f.raw_evidence = output;
                                f.category = "network/nmap-script".to_owned();
                                f.severity = severity_from_script_id(&script_id);
                                f.recommendation =
                                    "Review script findings and apply appropriate patches."
                                        .to_owned();
                                f.truncate_evidence(4096);
                                findings.push(f);
                            }
                        }
                        _ => {}
                    }

                    // Open port with known service → emit an informational finding
                    if tag == "port" && !current_host.is_empty() && current_state == "open" {
                        let title = if current_service.is_empty() {
                            format!("Open Port {current_port}/{current_proto}")
                        } else {
                            format!(
                                "Open Port {current_port}/{current_proto} ({current_service})"
                            )
                        };
                        let mut f = Finding::new(scan_id, title);
                        f.host = current_host.clone();
                        f.port = Some(current_port);
                        f.protocol = Some(current_proto.clone());
                        f.severity = Severity::Info;
                        f.category = "network/open-port".to_owned();
                        f.description = format!(
                            "Port {current_port}/{current_proto} is open on {current_host}."
                        );
                        f.recommendation = "Verify this port is intentionally exposed.".to_owned();
                        findings.push(f);
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(anyhow::anyhow!("nmap XML parse error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        Ok(findings)
    }
}

fn attr_value<'a>(
    e: &'a quick_xml::events::BytesStart<'a>,
    key: &[u8],
) -> Option<&'a str> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .and_then(|a| std::str::from_utf8(a.value.as_ref()).ok())
        // SAFETY: lifetime tied to the BytesStart, which lives long enough in our loop
        .map(|s| unsafe { std::mem::transmute::<&str, &'a str>(s) })
}

fn severity_from_script_id(id: &str) -> Severity {
    let lower = id.to_lowercase();
    if lower.contains("vuln") || lower.contains("exploit") || lower.contains("dos") {
        Severity::High
    } else if lower.contains("ssl") || lower.contains("tls") || lower.contains("weak") {
        Severity::Medium
    } else {
        Severity::Info
    }
}
