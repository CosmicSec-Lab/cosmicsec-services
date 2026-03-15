"""
Defensive AI Module - Auto-remediation and Defensive Recommendations
Part of Phase 4 - Innovation & Differentiation
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
import json


class DefensiveAI:
    """AI-powered defensive security and auto-remediation engine"""

    def __init__(self):
        # Remediation knowledge base
        self.remediation_db = self._load_remediation_kb()

    def _load_remediation_kb(self) -> Dict[str, Any]:
        """Load remediation knowledge base for common vulnerabilities"""
        return {
            "SQL_INJECTION": {
                "severity": "critical",
                "remediation_steps": [
                    "Use parameterized queries or prepared statements",
                    "Implement input validation and sanitization",
                    "Use ORM frameworks with built-in protection",
                    "Apply least privilege database permissions",
                    "Enable SQL injection detection in WAF"
                ],
                "code_snippets": {
                    "python": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                    "java": "PreparedStatement pstmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?');",
                    "nodejs": "db.query('SELECT * FROM users WHERE id = $1', [userId])"
                },
                "config_changes": [
                    "Enable ModSecurity SQL injection rules",
                    "Configure database firewall",
                    "Enable query logging for anomaly detection"
                ]
            },
            "XSS": {
                "severity": "high",
                "remediation_steps": [
                    "Encode all user input before rendering",
                    "Implement Content Security Policy (CSP)",
                    "Use auto-escaping template engines",
                    "Sanitize HTML input with allowlist",
                    "Enable HTTPOnly and Secure flags on cookies"
                ],
                "code_snippets": {
                    "python": "from markupsafe import escape\noutput = escape(user_input)",
                    "javascript": "const sanitized = DOMPurify.sanitize(userInput);",
                    "java": "String encoded = StringEscapeUtils.escapeHtml4(userInput);"
                },
                "config_changes": [
                    "Add CSP header: Content-Security-Policy: default-src 'self'",
                    "Enable XSS protection: X-XSS-Protection: 1; mode=block",
                    "Set X-Content-Type-Options: nosniff"
                ]
            },
            "CSRF": {
                "severity": "high",
                "remediation_steps": [
                    "Implement CSRF tokens for all state-changing operations",
                    "Use SameSite cookie attribute",
                    "Verify origin and referer headers",
                    "Implement double-submit cookie pattern",
                    "Use framework-provided CSRF protection"
                ],
                "code_snippets": {
                    "python": "@csrf_protect\ndef sensitive_action(request):\n    # Protected endpoint",
                    "nodejs": "app.use(csrf({ cookie: true }));",
                    "java": "@EnableWebSecurity\npublic class SecurityConfig extends WebSecurityConfigurerAdapter"
                },
                "config_changes": [
                    "Set SameSite=Strict on session cookies",
                    "Enable CSRF middleware in framework",
                    "Configure CORS properly"
                ]
            },
            "INSECURE_DESERIALIZATION": {
                "severity": "critical",
                "remediation_steps": [
                    "Avoid deserializing untrusted data",
                    "Use safe serialization formats (JSON, not pickle)",
                    "Implement integrity checks on serialized data",
                    "Use allow-list for deserializable classes",
                    "Run deserialization in isolated sandbox"
                ],
                "code_snippets": {
                    "python": "data = json.loads(untrusted_input)  # Instead of pickle.loads",
                    "java": "// Use JSON instead of ObjectInputStream for untrusted data",
                    "nodejs": "JSON.parse(data)  // Instead of eval() or node-serialize"
                },
                "config_changes": [
                    "Disable dangerous deserialization libraries",
                    "Configure serialization filters",
                    "Enable deserialization attack detection"
                ]
            },
            "WEAK_CRYPTOGRAPHY": {
                "severity": "high",
                "remediation_steps": [
                    "Use AES-256-GCM or ChaCha20-Poly1305 for encryption",
                    "Implement bcrypt or Argon2 for password hashing",
                    "Use TLS 1.3 for transport security",
                    "Generate cryptographically secure random numbers",
                    "Rotate encryption keys regularly"
                ],
                "code_snippets": {
                    "python": "from cryptography.fernet import Fernet\ncipher = Fernet.generate_key()",
                    "java": "Cipher cipher = Cipher.getInstance('AES/GCM/NoPadding');",
                    "nodejs": "const crypto = require('crypto');\nconst key = crypto.randomBytes(32);"
                },
                "config_changes": [
                    "Disable SSL/TLS < 1.2",
                    "Configure strong cipher suites",
                    "Enable forward secrecy"
                ]
            },
            "BROKEN_AUTHENTICATION": {
                "severity": "critical",
                "remediation_steps": [
                    "Implement multi-factor authentication",
                    "Use secure session management",
                    "Enforce strong password policies",
                    "Implement account lockout after failed attempts",
                    "Use secure password reset mechanism"
                ],
                "code_snippets": {
                    "python": "password_context = CryptContext(schemes=['bcrypt'])",
                    "java": "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();",
                    "nodejs": "const hash = await bcrypt.hash(password, 10);"
                },
                "config_changes": [
                    "Set session timeout to 15-30 minutes",
                    "Enable secure and HTTPOnly cookie flags",
                    "Implement rate limiting on auth endpoints"
                ]
            },
            "SSRF": {
                "severity": "high",
                "remediation_steps": [
                    "Validate and sanitize all URLs",
                    "Use allowlist for allowed domains",
                    "Disable redirects for outbound requests",
                    "Implement network segmentation",
                    "Use DNS resolution filtering"
                ],
                "code_snippets": {
                    "python": "allowed_domains = ['api.example.com']\nif urlparse(url).netloc not in allowed_domains:\n    raise ValueError('Invalid domain')",
                    "java": "// Validate URL against allowlist before making request",
                    "nodejs": "const validDomains = ['api.example.com'];\nif (!validDomains.includes(new URL(url).hostname)) throw new Error();"
                },
                "config_changes": [
                    "Configure egress firewall rules",
                    "Disable metadata service access (169.254.169.254)",
                    "Implement URL validation proxy"
                ]
            },
            "COMMAND_INJECTION": {
                "severity": "critical",
                "remediation_steps": [
                    "Never pass user input directly to system commands",
                    "Use parameterized APIs instead of shell commands",
                    "Implement strict input validation",
                    "Use allow-list for permitted characters",
                    "Run commands in isolated containers"
                ],
                "code_snippets": {
                    "python": "subprocess.run(['ls', '-la', safe_path], shell=False)  # Never use shell=True",
                    "java": "ProcessBuilder pb = new ProcessBuilder('ls', '-la', safePath);",
                    "nodejs": "execFile('ls', ['-la', safePath])  // Instead of exec()"
                },
                "config_changes": [
                    "Run application with minimal privileges",
                    "Enable seccomp filters to restrict syscalls",
                    "Configure SELinux/AppArmor policies"
                ]
            }
        }

    def suggest_remediation(self, vulnerability_type: str, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate AI-powered remediation suggestions for a vulnerability"""
        vuln_type = vulnerability_type.upper().replace(" ", "_")

        if vuln_type not in self.remediation_db:
            # Generic remediation for unknown types
            return {
                "vulnerability": vulnerability_type,
                "severity": "medium",
                "auto_remediable": False,
                "remediation_steps": [
                    "Review security best practices for this vulnerability type",
                    "Consult OWASP Top 10 guidelines",
                    "Implement defense-in-depth security controls",
                    "Conduct security code review",
                    "Apply security patches if available"
                ],
                "estimated_effort": "medium",
                "priority": "medium",
                "timestamp": datetime.utcnow().isoformat()
            }

        kb_entry = self.remediation_db[vuln_type]

        # Determine if auto-remediation is possible
        auto_remediable = self._can_auto_remediate(vuln_type, finding)

        return {
            "vulnerability": vulnerability_type,
            "severity": kb_entry["severity"],
            "auto_remediable": auto_remediable,
            "remediation_steps": kb_entry["remediation_steps"],
            "code_snippets": kb_entry.get("code_snippets", {}),
            "config_changes": kb_entry.get("config_changes", []),
            "estimated_effort": self._estimate_effort(vuln_type),
            "priority": self._calculate_priority(kb_entry["severity"], finding),
            "affected_components": finding.get("affected_components", []),
            "timestamp": datetime.utcnow().isoformat()
        }

    def _can_auto_remediate(self, vuln_type: str, finding: Dict[str, Any]) -> bool:
        """Determine if vulnerability can be automatically remediated"""
        # Configuration-based vulnerabilities are often auto-remediable
        config_based = ["WEAK_CRYPTOGRAPHY", "BROKEN_AUTHENTICATION", "CSRF"]

        # Check if we have configuration changes available
        if vuln_type in config_based and vuln_type in self.remediation_db:
            return len(self.remediation_db[vuln_type].get("config_changes", [])) > 0

        return False

    def _estimate_effort(self, vuln_type: str) -> str:
        """Estimate remediation effort"""
        high_effort = ["SQL_INJECTION", "INSECURE_DESERIALIZATION", "COMMAND_INJECTION"]
        low_effort = ["CSRF", "WEAK_CRYPTOGRAPHY"]

        if vuln_type in high_effort:
            return "high"
        elif vuln_type in low_effort:
            return "low"
        return "medium"

    def _calculate_priority(self, severity: str, finding: Dict[str, Any]) -> str:
        """Calculate remediation priority based on severity and context"""
        # Priority matrix
        if severity == "critical":
            return "critical"
        elif severity == "high":
            # Upgrade to critical if exposed to internet
            if finding.get("internet_facing", False):
                return "critical"
            return "high"
        elif severity == "medium":
            return "medium"
        return "low"

    def generate_security_hardening(self, system_type: str) -> Dict[str, Any]:
        """Generate security hardening recommendations for different system types"""
        hardening_guides = {
            "web_application": {
                "server_hardening": [
                    "Disable unnecessary services and ports",
                    "Enable firewall with least-privilege rules",
                    "Configure fail2ban for intrusion prevention",
                    "Enable automatic security updates",
                    "Implement rate limiting on all endpoints"
                ],
                "application_hardening": [
                    "Enable all security headers (CSP, HSTS, X-Frame-Options)",
                    "Implement input validation on all user inputs",
                    "Use parameterized queries for database access",
                    "Enable CSRF protection on all forms",
                    "Implement proper session management"
                ],
                "database_hardening": [
                    "Use least-privilege database accounts",
                    "Enable database encryption at rest",
                    "Implement database firewall rules",
                    "Enable query logging and monitoring",
                    "Regular backup and recovery testing"
                ]
            },
            "api": {
                "authentication": [
                    "Implement OAuth 2.0 or JWT authentication",
                    "Use API keys with rate limiting",
                    "Enable mutual TLS for sensitive endpoints",
                    "Implement token rotation",
                    "Add request signing for integrity"
                ],
                "authorization": [
                    "Implement RBAC or ABAC",
                    "Validate permissions on every request",
                    "Use principle of least privilege",
                    "Implement resource-level authorization",
                    "Log all authorization decisions"
                ],
                "data_protection": [
                    "Encrypt sensitive data in transit and at rest",
                    "Implement field-level encryption for PII",
                    "Use data masking for logs",
                    "Implement data retention policies",
                    "Enable HTTPS/TLS 1.3 only"
                ]
            },
            "cloud_infrastructure": {
                "iam": [
                    "Enable MFA for all users",
                    "Use least-privilege IAM policies",
                    "Rotate access keys every 90 days",
                    "Enable CloudTrail/activity logging",
                    "Implement role-based access control"
                ],
                "network": [
                    "Implement network segmentation (VPC/subnets)",
                    "Use security groups with least-privilege rules",
                    "Enable VPC flow logs",
                    "Implement WAF for public endpoints",
                    "Use private subnets for sensitive resources"
                ],
                "data": [
                    "Enable encryption at rest for all storage",
                    "Use KMS for key management",
                    "Implement bucket/blob policies",
                    "Enable versioning and lifecycle policies",
                    "Regular backup and disaster recovery testing"
                ]
            }
        }

        return {
            "system_type": system_type,
            "hardening_recommendations": hardening_guides.get(system_type, {}),
            "compliance_frameworks": ["NIST CSF", "CIS Benchmarks", "OWASP Top 10"],
            "automated_tools": [
                "OWASP ZAP for security testing",
                "ModSecurity for WAF",
                "Fail2ban for intrusion prevention",
                "Lynis for system hardening audit"
            ],
            "timestamp": datetime.utcnow().isoformat()
        }

    def generate_incident_response_plan(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate incident response plan for a discovered vulnerability"""
        severity = vulnerability.get("severity", "medium")

        response_plans = {
            "critical": {
                "immediate_actions": [
                    "Activate incident response team immediately",
                    "Isolate affected systems if actively exploited",
                    "Notify security team and management",
                    "Begin evidence collection and preservation",
                    "Implement temporary workarounds if possible"
                ],
                "timeline": "0-1 hours",
                "escalation_required": True
            },
            "high": {
                "immediate_actions": [
                    "Notify security team",
                    "Assess risk and exploitation potential",
                    "Plan remediation timeline",
                    "Monitor for exploitation attempts",
                    "Prepare patches or configuration changes"
                ],
                "timeline": "1-24 hours",
                "escalation_required": True
            },
            "medium": {
                "immediate_actions": [
                    "Document the finding",
                    "Add to remediation backlog",
                    "Assess business risk",
                    "Plan remediation in next sprint",
                    "Implement monitoring if needed"
                ],
                "timeline": "1-7 days",
                "escalation_required": False
            }
        }

        plan = response_plans.get(severity, response_plans["medium"])

        return {
            "vulnerability_id": vulnerability.get("id", "unknown"),
            "severity": severity,
            "response_plan": plan,
            "communication_plan": {
                "internal": ["Security team", "Development team", "Management"],
                "external": ["Customers (if data breach)", "Regulators (if required)"]
            },
            "recovery_steps": [
                "Apply security patches",
                "Verify remediation effectiveness",
                "Update security documentation",
                "Conduct lessons learned session",
                "Update detection rules"
            ],
            "timestamp": datetime.utcnow().isoformat()
        }
