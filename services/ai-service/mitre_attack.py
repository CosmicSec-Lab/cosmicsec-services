"""
Phase 2 — MITRE ATT&CK correlation engine.

Maps vulnerability / finding titles to ATT&CK tactics, techniques,
and their recommended mitigations.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# ATT&CK technique registry (curated subset relevant to appsec/infrasec)
# ---------------------------------------------------------------------------
_TECHNIQUE_REGISTRY: List[Dict[str, str]] = [
    {
        "keywords": "sql injection|sqli|sql",
        "tactic": "Initial Access / Execution",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "mitigation": "Parameterised queries, WAF, input validation, least-privilege DB user. M1051 Update Software.",
    },
    {
        "keywords": "xss|cross.site scripting|reflected|stored xss|dom xss",
        "tactic": "Collection / Defense Evasion",
        "technique_id": "T1185",
        "technique_name": "Browser Session Hijacking",
        "mitigation": "Strict CSP, output encoding, HttpOnly cookies, SameSite cookie attribute.",
    },
    {
        "keywords": r"\brce\b|remote code execution|command injection|os command|code injection",
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "mitigation": "Application allowlisting, input sanitisation, disable unnecessary shells, process monitoring.",
    },
    {
        "keywords": "ssrf|server.side request forgery|metadata endpoint",
        "tactic": "Discovery / Lateral Movement",
        "technique_id": "T1090",
        "technique_name": "Proxy / Internal Network Recon via SSRF",
        "mitigation": "URL allowlist, block private/metadata IPs, IMDSv2 enforcement.",
    },
    {
        "keywords": "xxe|xml external entity|xml injection",
        "tactic": "Exfiltration",
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service (via XXE OOB)",
        "mitigation": "Disable external entity processing in XML parsers, use JSON alternatives.",
    },
    {
        "keywords": "idor|insecure direct object|broken access control|privilege escalation|unauthorised access",
        "tactic": "Privilege Escalation / Collection",
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "mitigation": "Server-side authorisation checks on every request. RBAC with deny-by-default. Audit access logs.",
    },
    {
        "keywords": "brute force|password spray|credential stuffing|account lockout",
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "mitigation": "Account lockout, MFA, adaptive authentication, monitor failed logins, CAPTCHA.",
    },
    {
        "keywords": "weak password|default password|hardcoded credential|plaintext password",
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "mitigation": "Enforce strong password policy, secrets managers (Vault, AWS Secrets Manager), rotate credentials.",
    },
    {
        "keywords": "log4shell|log4j|cve-2021-44228|jndi injection",
        "tactic": "Initial Access / Execution",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (Log4Shell)",
        "mitigation": "Upgrade log4j >= 2.17.1. Block JNDI lookup patterns at WAF. Isolate vulnerable systems.",
    },
    {
        "keywords": "spring4shell|spring framework|cve-2022-22965",
        "tactic": "Initial Access / Execution",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (Spring4Shell)",
        "mitigation": "Upgrade Spring >= 5.3.18. Apply WAF rule blocking class.classLoader prefix.",
    },
    {
        "keywords": "deserialization|insecure deserialization|java deserialization|pickle",
        "tactic": "Execution",
        "technique_id": "T1059.007",
        "technique_name": "JavaScript/Python Deserialization (Execution via Serialised Data)",
        "mitigation": "Avoid deserialising untrusted data. Use safe formats (JSON). Apply type-safe deserialisation.",
    },
    {
        "keywords": "open redirect|unvalidated redirect|phishing|url manipulation",
        "tactic": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing via Open Redirect",
        "mitigation": "Validate redirect URLs against allowlist. Strip redirect parameters for third-party URLs.",
    },
    {
        "keywords": "directory traversal|path traversal|local file inclusion|lfi",
        "tactic": "Collection / Discovery",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "mitigation": "Canonicalise paths, jail file access to safe roots, never pass user input directly to filesystem.",
    },
    {
        "keywords": "misconfiguration|debug mode|exposed admin|default config",
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (Misconfiguration)",
        "mitigation": "Apply CIS benchmarks, disable debug endpoints, automated config scanning in CI/CD.",
    },
    {
        "keywords": "outdated|vulnerable component|dependency|cve|known vulnerability",
        "tactic": "Initial Access",
        "technique_id": "T1195",
        "technique_name": "Supply Chain Compromise / Outdated Component",
        "mitigation": "SCA scanning (Snyk, Dependabot), SBOM generation, rapid CVE patching SLA.",
    },
    {
        "keywords": "ransomware|data encryption|backup|extortion",
        "tactic": "Impact",
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "mitigation": "Offline 3-2-1 backups, endpoint detection, disable macros, network segmentation.",
    },
    {
        "keywords": "c2|command and control|beacon|reverse shell|malware|exfiltration",
        "tactic": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2 over HTTP/S/DNS)",
        "mitigation": "Egress filtering, DNS filtering, network behaviour analytics, TLS inspection.",
    },
    {
        "keywords": "s3 bucket|blob storage|public bucket|cloud storage exposure",
        "tactic": "Exfiltration",
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object",
        "mitigation": "Block public ACLs, enable bucket-level logging, use AWS Macie / Azure Defender for Storage.",
    },
    {
        "keywords": "kubernetes|k8s|container escape|pod security|privileged container",
        "tactic": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
        "mitigation": "Restrict privileged containers, apply Pod Security Standards, enable RBAC least-privilege, network policies.",
    },
    {
        "keywords": "jwt|token|session fixation|session hijack|oauth|bearer",
        "tactic": "Credential Access / Lateral Movement",
        "technique_id": "T1550",
        "technique_name": "Use Alternate Authentication Material",
        "mitigation": "Short token TTLs, token rotation on privilege change, strong JWT signing (RS256/ES256), revocation lists.",
    },
]

_FALLBACK: Dict[str, str] = {
    "tactic": "Undetermined",
    "technique_id": "T0000",
    "technique_name": "Unknown Technique",
    "mitigation": "Review the finding manually against the MITRE ATT&CK framework at https://attack.mitre.org",
}


def map_to_attack(finding: str) -> Dict[str, str]:
    """
    Map a finding title / description to the most relevant MITRE ATT&CK entry.

    Args:
        finding: Raw vulnerability / finding text.

    Returns:
        Dict with keys: tactic, technique_id, technique_name, mitigation.
    """
    lower = finding.lower()
    for entry in _TECHNIQUE_REGISTRY:
        if re.search(entry["keywords"], lower):
            return {
                "tactic": entry["tactic"],
                "technique_id": entry["technique_id"],
                "technique_name": entry["technique_name"],
                "mitigation": entry["mitigation"],
            }
    return dict(_FALLBACK)


def map_multiple(findings: List[str]) -> List[Dict[str, str]]:
    """Map a list of finding strings to ATT&CK entries."""
    return [{"finding": f, **map_to_attack(f)} for f in findings]
