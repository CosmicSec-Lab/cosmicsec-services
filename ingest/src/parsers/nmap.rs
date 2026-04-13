/// Nmap XML output parser.
use std::collections::HashMap;

use xml::reader::{EventReader, XmlEvent};

use crate::error::ParseError;
use crate::schema::{Finding, SeverityLevel};

/// Map a port number to a severity level.
fn severity_for_port(port: u16) -> SeverityLevel {
    match port {
        21 => SeverityLevel::Medium,   // FTP
        22 => SeverityLevel::Low,      // SSH
        23 => SeverityLevel::High,     // Telnet
        25 => SeverityLevel::Medium,   // SMTP
        53 => SeverityLevel::Low,      // DNS
        80 | 8080 | 8443 => SeverityLevel::Info, // HTTP
        110 => SeverityLevel::Medium,  // POP3
        111 => SeverityLevel::Medium,  // rpcbind
        135 => SeverityLevel::Medium,  // MSRPC
        139 => SeverityLevel::Medium,  // NetBIOS
        143 => SeverityLevel::Medium,  // IMAP
        161 => SeverityLevel::Medium,  // SNMP
        389 => SeverityLevel::Medium,  // LDAP
        443 => SeverityLevel::Info,    // HTTPS
        445 => SeverityLevel::High,    // SMB
        512..=514 => SeverityLevel::High, // rexec / rlogin / rsh
        1433 => SeverityLevel::High,   // MSSQL
        1521 => SeverityLevel::High,   // Oracle DB
        2049 => SeverityLevel::Medium, // NFS
        3306 => SeverityLevel::Medium, // MySQL
        3389 => SeverityLevel::High,   // RDP
        5432 => SeverityLevel::Medium, // PostgreSQL
        5900 => SeverityLevel::High,   // VNC
        6379 => SeverityLevel::High,   // Redis
        9200 => SeverityLevel::High,   // Elasticsearch
        27017 => SeverityLevel::High,  // MongoDB
        _ => SeverityLevel::Info,
    }
}

/// Parse nmap XML output and return a list of findings.
///
/// Each open port becomes one finding.  Service and version information is
/// included in the description when available.
pub fn parse_nmap_xml(xml_str: &str) -> Result<Vec<Finding>, ParseError> {
    let reader = EventReader::from_str(xml_str);
    let mut findings: Vec<Finding> = Vec::new();

    // State machine
    let mut current_host: Option<String> = None;
    let mut current_port: Option<(u16, String)> = None; // (portid, protocol)
    let mut port_is_open = false;
    let mut service_attrs: HashMap<String, String> = HashMap::new();

    for event in reader {
        match event? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                let local = name.local_name.as_str();
                let attrs: HashMap<String, String> = attributes
                    .into_iter()
                    .map(|a| (a.name.local_name, a.value))
                    .collect();

                match local {
                    "address" if attrs.get("addrtype").map(|s| s.as_str()) == Some("ipv4")
                        || attrs.get("addrtype").map(|s| s.as_str()) == Some("ipv6") =>
                    {
                        current_host = attrs.get("addr").cloned();
                    }
                    "port" => {
                        let portid: u16 = attrs
                            .get("portid")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let proto = attrs.get("protocol").cloned().unwrap_or_default();
                        current_port = Some((portid, proto));
                        port_is_open = false;
                        service_attrs.clear();
                    }
                    "state" => {
                        if attrs.get("state").map(|s| s.as_str()) == Some("open") {
                            port_is_open = true;
                        }
                    }
                    "service" => {
                        service_attrs = attrs;
                    }
                    _ => {}
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == "port" {
                    if port_is_open {
                        if let (Some(ref host), Some((portid, ref proto))) =
                            (&current_host, &current_port)
                        {
                            let service_name = service_attrs
                                .get("name")
                                .cloned()
                                .unwrap_or_else(|| "unknown".to_string());
                            let product = service_attrs.get("product").cloned().unwrap_or_default();
                            let version = service_attrs.get("version").cloned().unwrap_or_default();
                            let svc_ver = format!("{} {}", product, version).trim().to_string();

                            let severity = severity_for_port(*portid);
                            let mut description = format!(
                                "Port {}/{} is open — service: {}",
                                portid, proto, service_name
                            );
                            if !svc_ver.is_empty() {
                                description.push_str(&format!(" ({})", svc_ver));
                            }

                            findings.push(Finding::new(
                                format!("Open port {}/{} ({})", portid, proto, service_name),
                                severity,
                                description,
                                format!("{}:{}/{}", host, portid, proto),
                                "nmap",
                                host.clone(),
                            ));
                        }
                    }
                    current_port = None;
                    port_is_open = false;
                    service_attrs.clear();
                }
            }
            _ => {}
        }
    }

    Ok(findings)
}
