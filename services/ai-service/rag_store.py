"""
RAG Store — TF-IDF knowledge retrieval for Helix AI.

Phase 1: TF-IDF similarity over embedded security knowledge base.
Phase 2 upgrade path: swap for ChromaDB / Pinecone vector store.
"""
from __future__ import annotations

from typing import Dict, List, Optional

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-not-found]
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore[import-not-found]
    import numpy as np  # type: ignore[import-not-found]
    _SKLEARN_AVAILABLE = True
except Exception:
    _SKLEARN_AVAILABLE = False

# ---------------------------------------------------------------------------
# Security knowledge base — 50+ entries covering OWASP Top 10, CWE and
# common pentesting finding categories with actionable remediation guidance.
# ---------------------------------------------------------------------------
SECURITY_KB: List[Dict[str, str]] = [
    # --- Injection ---
    {"topic": "sql injection sqli sql-injection",
     "guidance": "Use parameterised queries or prepared statements. Validate and sanitise all user-supplied input. Apply the principle of least-privilege for database accounts."},
    {"topic": "nosql injection mongodb",
     "guidance": "Sanitise query operators ($where, $regex). Use schema validation; never pass raw user input directly to NoSQL query builders."},
    {"topic": "command injection os injection rce remote code execution",
     "guidance": "Avoid using shell=True; use subprocess with argument lists. Whitelist allowed commands. Apply OS-level sandboxing (seccomp, AppArmor)."},
    {"topic": "ldap injection",
     "guidance": "Escape special LDAP characters. Use server-side input validation and parameterised LDAP queries."},
    {"topic": "template injection ssti server-side template",
     "guidance": "Never pass user input directly to template engines. Use sandboxed template contexts and disable dangerous template features."},
    # --- XSS ---
    {"topic": "xss cross-site scripting reflected stored dom",
     "guidance": "Encode output with context-aware escaping. Implement a strict Content-Security-Policy (CSP). Use HttpOnly and SameSite cookie flags."},
    # --- Broken Access Control ---
    {"topic": "idor insecure direct object reference broken access control",
     "guidance": "Enforce authorisation checks server-side for every object access. Use indirect object references (UUIDs, opaque tokens). Implement RBAC or ABAC."},
    {"topic": "privilege escalation horizontal vertical access control",
     "guidance": "Deny by default; allow only explicitly permitted actions. Log and alert on permission changes. Use Casbin or OPA for fine-grained RBAC/ABAC."},
    {"topic": "path traversal directory traversal lfi local file inclusion",
     "guidance": "Canonicalise file paths and validate against an allowlist. Run processes with minimal filesystem permissions. Use chroot jails where applicable."},
    # --- Cryptographic Failures ---
    {"topic": "weak encryption md5 sha1 des ecb plaintext password storage",
     "guidance": "Use AES-256-GCM or ChaCha20-Poly1305 for encryption. Use bcrypt, scrypt, or Argon2id for password hashing. Enforce TLS 1.2+ with strong cipher suites."},
    {"topic": "tls ssl certificate misconfiguration expired",
     "guidance": "Enforce TLS 1.3. Disable SSLv3/TLS 1.0/1.1. Automate certificate renewal with Let's Encrypt / ACME. Pin certificates for critical services."},
    {"topic": "hardcoded secrets api keys credentials in code",
     "guidance": "Rotate all exposed secrets immediately. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager). Add pre-commit hooks with TruffleHog / GitGuardian."},
    # --- Security Misconfiguration ---
    {"topic": "missing security headers csp hsts x-frame-options",
     "guidance": "Set CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, HSTS with preload, and Referrer-Policy. Use Mozilla Observatory to validate."},
    {"topic": "open ports exposed services network misconfiguration",
     "guidance": "Limit externally exposed ports; enforce ingress allowlists. Segment networks. Apply MFA for all admin services. Run regular firewall rule reviews."},
    {"topic": "debug mode verbose error information disclosure",
     "guidance": "Disable debug mode in production. Return generic error messages to clients. Log full details server-side only with appropriate access controls."},
    {"topic": "default credentials default password admin admin",
     "guidance": "Change all default credentials before deployment. Enforce password complexity policies. Implement MFA for all admin accounts."},
    {"topic": "cors misconfiguration cross-origin",
     "guidance": "Restrict Access-Control-Allow-Origin to specific trusted origins. Never use wildcard (*) with credentials. Validate Origin header server-side."},
    # --- Vulnerable Components ---
    {"topic": "outdated dependencies vulnerable libraries cve",
     "guidance": "Implement automated SCA scanning (Snyk, Dependabot, Trivy). Subscribe to security advisories. Maintain an SBOM. Apply patches within SLA."},
    {"topic": "log4shell log4j cve-2021-44228",
     "guidance": "Upgrade log4j to ≥2.17.1. Block $ in JNDI lookups at WAF. Isolate affected systems immediately and scan for exploitation indicators."},
    {"topic": "spring4shell spring rce cve-2022-22965",
     "guidance": "Upgrade Spring Framework to ≥5.3.18 / 5.2.20. Apply WAF rules blocking class.classLoader patterns."},
    # --- Authentication Failures ---
    {"topic": "brute force account lockout rate limiting",
     "guidance": "Implement account lockout after N failures. Add progressive delays. Apply rate limiting with IP-based and user-based throttling. Use CAPTCHA."},
    {"topic": "session fixation session hijacking cookie theft",
     "guidance": "Regenerate session IDs on privilege change. Use HttpOnly, Secure, and SameSite=Strict cookie flags. Implement absolute session timeouts."},
    {"topic": "jwt misconfiguration none algorithm algorithm confusion",
     "guidance": "Reject tokens with alg=none. Verify algorithm explicitly (allowlist). Use RS256 or ES256 in production. Validate exp, iss, and aud claims."},
    {"topic": "oauth misconfiguration redirect uri open redirect",
     "guidance": "Validate redirect_uri against a server-side allowlist. Use PKCE for public clients. Validate state parameter to prevent CSRF in OAuth flows."},
    # --- SSRF ---
    {"topic": "ssrf server-side request forgery internal metadata cloud",
     "guidance": "Validate and sanitise URLs before server-side fetches. Enforce network egress allowlists. Block metadata endpoints (169.254.169.254). Use IMDSv2 on AWS."},
    # --- XXE ---
    {"topic": "xxe xml external entity injection",
     "guidance": "Disable external entity processing in XML parsers (FEATURE_EXTERNAL_GENERAL_ENTITIES=false). Prefer JSON. Use defusedxml library in Python."},
    # --- Deserialization ---
    {"topic": "insecure deserialization pickle java serialization",
     "guidance": "Never deserialise untrusted data. Use safe formats (JSON, Protobuf). Implement integrity validation (HMAC signing) before deserialisation."},
    # --- Infrastructure / Cloud ---
    {"topic": "s3 bucket misconfiguration public bucket aws",
     "guidance": "Enable S3 Block Public Access at account level. Apply bucket policies with explicit deny for s3:GetObject unless authenticated. Enable access logging."},
    {"topic": "kubernetes misconfiguration rbac cluster-admin",
     "guidance": "Apply principle of least privilege with RBAC. Disable anonymous API access. Use PodSecurity admission, network policies, and Falco for runtime detection."},
    {"topic": "container escape docker privileged root",
     "guidance": "Run containers as non-root. Drop Linux capabilities. Use read-only root filesystems. Apply seccomp and AppArmor profiles. Avoid --privileged flag."},
    # --- Application Logic ---
    {"topic": "business logic race condition toctou",
     "guidance": "Implement idempotency tokens for critical operations. Use database-level locking for inventory/balance updates. Validate state transitions server-side."},
    {"topic": "mass assignment parameter pollution",
     "guidance": "Use explicit allow-lists for model binding. Never bind request data directly to ORM models. Validate and strip unexpected parameters."},
    {"topic": "file upload unrestricted upload webshell",
     "guidance": "Validate file type by magic bytes, not extension. Store uploads outside webroot. Serve via CDN with content-type enforcement. Scan with AV/sandbox."},
    # --- Phishing / Social Engineering ---
    {"topic": "phishing spearphishing email spoofing",
     "guidance": "Configure SPF, DKIM, and DMARC records. Train users on phishing indicators. Deploy email security gateways with sandbox analysis."},
    # --- Denial of Service ---
    {"topic": "dos ddos resource exhaustion",
     "guidance": "Implement rate limiting at multiple layers. Use CDN with DDoS protection. Apply connection limits. Implement circuit breakers for downstream services."},
    # --- Recon / Information Leakage ---
    {"topic": "subdomain enumeration dns recon",
     "guidance": "Audit DNS records regularly. Remove stale CNAME records (dangling DNS). Use DNSSEC. Monitor for subdomain takeover with automated tooling."},
    {"topic": "git exposed repository source code leak",
     "guidance": "Add web server rules to deny access to .git directories. Use pre-commit hooks to prevent committing secrets. Monitor with GitGuardian."},
    # --- DevSecOps ---
    {"topic": "ci cd pipeline security supply chain",
     "guidance": "Pin dependency versions and verify checksums. Sign build artifacts with Sigstore/Cosign. Isolate build environments. Enforce branch protection rules."},
    {"topic": "infrastructure as code iac terraform misconfiguration",
     "guidance": "Scan IaC with Checkov, tfsec, or Terrascan. Enforce tagging policies. Use read-only IAM roles for CI/CD. Review plan output before apply."},
    # --- Zero Trust ---
    {"topic": "zero trust network access microsegmentation",
     "guidance": "Implement identity-aware proxy (BeyondCorp model). Enforce device posture checks. Apply east-west traffic controls with network policies (Cilium/Calico)."},
    # --- Compliance ---
    {"topic": "pci dss compliance",
     "guidance": "Segment CDE from non-CDE networks. Encrypt CHD at rest and in transit. Maintain vulnerability management program. Conduct annual pen tests."},
    {"topic": "gdpr data privacy",
     "guidance": "Implement data minimisation and purpose limitation. Enable right to erasure workflows. Encrypt PII at rest and in transit. Maintain processing records."},
    # --- General Best Practices ---
    {"topic": "logging monitoring audit trail",
     "guidance": "Log all security events (auth, privilege changes, errors). Centralise logs in a SIEM. Implement alerts for anomalies. Retain logs per compliance requirements."},
    {"topic": "patch management vulnerability management",
     "guidance": "Maintain an asset inventory. Subscribe to security advisories. Define patching SLAs by severity (critical ≤24h, high ≤7d). Automate where possible."},
    {"topic": "defence in depth layered security controls",
     "guidance": "Apply controls at every layer (network, host, application, data). Assume breach mindset. Implement detection and response capabilities alongside prevention."},
]

# ---------------------------------------------------------------------------
# Build TF-IDF index at module load time
# ---------------------------------------------------------------------------
_corpus: List[str] = [entry["topic"] for entry in SECURITY_KB]
_guidance: List[str] = [entry["guidance"] for entry in SECURITY_KB]
_vectorizer: Optional[object] = None
_tfidf_matrix: Optional[object] = None

if _SKLEARN_AVAILABLE:
    try:
        _vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        _tfidf_matrix = _vectorizer.fit_transform(_corpus)
    except Exception:
        _vectorizer = None
        _tfidf_matrix = None


def retrieve_guidance(text: str, top_k: int = 3) -> List[str]:
    """Return top-k guidance strings most relevant to *text*.

    Uses TF-IDF cosine similarity when scikit-learn is available;
    falls back to keyword substring matching otherwise.
    """
    if not text.strip():
        return ["Follow CIS benchmarks and enforce least-privilege access controls."]

    if _SKLEARN_AVAILABLE and _vectorizer is not None and _tfidf_matrix is not None:
        try:
            query_vec = _vectorizer.transform([text.lower()])  # type: ignore[union-attr]
            scores = cosine_similarity(query_vec, _tfidf_matrix).flatten()  # type: ignore[arg-type]
            top_indices = scores.argsort()[::-1][:top_k]
            results = [_guidance[i] for i in top_indices if scores[i] > 0.0]
            if results:
                return results
        except Exception:
            pass

    # Keyword fallback
    lowered = text.lower()
    hits = [
        entry["guidance"]
        for entry in SECURITY_KB
        if any(kw in lowered for kw in entry["topic"].split())
    ]
    return hits[:top_k] if hits else ["Follow CIS benchmarks and enforce least-privilege access controls."]
