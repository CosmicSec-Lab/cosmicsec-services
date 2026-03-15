"""
Phase 2 — ChromaDB Vector Store for Helix AI RAG pipeline.

Provides:
- Initialise a persistent ChromaDB collection.
- Ingest structured CVE / MITRE ATT&CK knowledge documents.
- Semantic search over the collection using embeddings.

If chromadb is not installed the module degrades gracefully to the
TF-IDF rag_store already available in Phase 1.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_CHROMA_AVAILABLE = False
_client = None
_collection = None

try:
    import chromadb  # type: ignore[import-not-found]
    from chromadb.config import Settings  # type: ignore[import-not-found]
    _CHROMA_AVAILABLE = True
except Exception:
    pass

_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "/tmp/cosmicsec_chroma")

# ---------------------------------------------------------------------------
# Document corpus — CVE categories + technique-level MITRE knowledge
# ---------------------------------------------------------------------------
_INITIAL_DOCUMENTS: List[Dict[str, str]] = [
    # MITRE ATT&CK Techniques
    {"id": "att-t1190", "text": "T1190 Exploit Public-Facing Application: Adversaries exploit vulnerabilities in internet-facing software to gain access. Remediation: patch promptly, apply WAF rules, and enable IDS."},
    {"id": "att-t1059", "text": "T1059 Command and Scripting Interpreter: Adversaries abuse command shells (bash, PowerShell, Python) for execution. Remediation: application allow-listing, disable unnecessary interpreters, log all shell executions."},
    {"id": "att-t1078", "text": "T1078 Valid Accounts: Use of legitimate credentials by adversaries. Remediation: enforce MFA, monitor for unusual login activity, apply least privilege, rotate credentials periodically."},
    {"id": "att-t1110", "text": "T1110 Brute Force: Password spraying, credential stuffing, or dictionary attacks. Remediation: account lockout policies, MFA, monitor for repeated auth failures, use adaptive authentication."},
    {"id": "att-t1055", "text": "T1055 Process Injection: Injecting code into processes to evade detection. Remediation: deploy EDR solutions, enable process monitoring, restrict debug privileges, use memory integrity."},
    {"id": "att-t1136", "text": "T1136 Create Account: Adversaries create accounts to maintain access. Remediation: monitor account creation events, enforce approval workflows, alert on new privileged accounts."},
    {"id": "att-t1071", "text": "T1071 Application Layer Protocol: C2 traffic over HTTP/S, DNS, or email. Remediation: inspect and filter protocol traffic, deploy DNS filtering, use network behaviour analytics."},
    {"id": "att-t1083", "text": "T1083 File and Directory Discovery: Enumeration of filesystem structure to find sensitive data. Remediation: restrict read permissions, audit access logs, deploy honeypot files."},
    {"id": "att-t1566", "text": "T1566 Phishing: Spearphishing emails with malicious links or attachments. Remediation: deploy email security gateway, train users, enable DMARC/DKIM/SPF, sandbox attachments."},
    {"id": "att-t1486", "text": "T1486 Data Encrypted for Impact (Ransomware): Encrypting files to extort victim. Remediation: offline backups (3-2-1), endpoint protection, disable macro execution, segment networks."},
    # CVE high-impact entries
    {"id": "cve-2021-44228", "text": "CVE-2021-44228 Log4Shell: JNDI injection in Apache Log4j2 allowing unauthenticated RCE. Upgrade to log4j >= 2.17.1. Block $ in JNDI lookups at WAF layer. Scan for exploitation IOCs."},
    {"id": "cve-2022-22965", "text": "CVE-2022-22965 Spring4Shell: Class-injection leading to RCE in Spring Framework. Upgrade to Spring >= 5.3.18. Apply WAF rules blocking class.classLoader patterns."},
    {"id": "cve-2021-26855", "text": "CVE-2021-26855 ProxyLogon: SSRF in Microsoft Exchange allowing unauthenticated access. Apply Microsoft security patches immediately. Check for web shells in Exchange directories."},
    {"id": "cve-2023-23397", "text": "CVE-2023-23397 Outlook NTLM relay: Zero-click LPE/credential theft via meeting invite. Apply Microsoft patch KB5023280. Block outbound SMB at firewall."},
    {"id": "cve-2023-44487", "text": "CVE-2023-44487 HTTP/2 Rapid Reset DDoS: Amplified DoS vector in HTTP/2. Update server software (nginx, nghttp2, IIS). Apply rate limiting on stream resets."},
    {"id": "cve-2023-4966", "text": "CVE-2023-4966 Citrix Bleed: Buffer overflow allowing session token extraction in NetScaler. Update to patched NetScaler versions immediately. Terminate all active sessions after patching."},
    {"id": "cve-2024-3400", "text": "CVE-2024-3400 PAN-OS GlobalProtect: Command injection RCE in Palo Alto firewall. Apply immediate hotfix. Enable Threat Prevention if licensed. Investigate for indicators of compromise."},
    # OWASP categories
    {"id": "owasp-a01", "text": "OWASP A01 Broken Access Control: Enforce authorisation server-side. Use deny-by-default. Implement RBAC with Casbin/OPA. Log and alert on access violations."},
    {"id": "owasp-a02", "text": "OWASP A02 Cryptographic Failures: Use AES-256-GCM for encryption. Use Argon2id/bcrypt for passwords. Enforce TLS 1.3. Never store secrets in code or env files committed to VCS."},
    {"id": "owasp-a03", "text": "OWASP A03 Injection (SQLi, XSS, LDAP, OS): Use parameterised queries y prepared statements. Encode output context-specifically. Apply input validation and output encoding libraries."},
    {"id": "owasp-a04", "text": "OWASP A04 Insecure Design: Threat model early. Use secure design patterns. Apply separation of privilege. Conduct architecture risk analysis."},
    {"id": "owasp-a05", "text": "OWASP A05 Security Misconfiguration: Automate hardening with CIS benchmarks. Disable debug endpoints in production. Use IaC scanning (Checkov, tfsec). Apply principle of least privilege everywhere."},
    {"id": "owasp-a06", "text": "OWASP A06 Vulnerable and Outdated Components: Implement SCA scanning (Snyk, Dependabot). Maintain SBOM. Patch critical CVEs within 24h. Subscribe to security advisories."},
    {"id": "owasp-a07", "text": "OWASP A07 Identification and Authentication Failures: Enforce MFA. Implement account lockout. Securely manage sessions (HttpOnly, SameSite, rotate on privilege change)."},
    {"id": "owasp-a08", "text": "OWASP A08 Software and Data Integrity Failures: Sign build artifacts (Sigstore/Cosign). Verify checksums. Use pinned dependency versions. Implement CI/CD security gates."},
    {"id": "owasp-a09", "text": "OWASP A09 Security Logging and Monitoring Failures: Centralise logs in SIEM. Alert on suspicious patterns. Maintain immutable audit trail. Test detection capabilities regularly."},
    {"id": "owasp-a10", "text": "OWASP A10 Server-Side Request Forgery (SSRF): Validate and restrict outgoing URLs. Block metadata endpoints. Use egress allowlists. Apply IMDSv2 on cloud instances."},
    # Cloud-specific
    {"id": "cloud-aws-iam", "text": "AWS IAM over-privilege: Use IAM Access Analyzer. Enforce SCP to restrict risky actions. Apply least privilege. Remove broad * permissions. Enable CloudTrail."},
    {"id": "cloud-azure-aad", "text": "Azure AD misconfiguration: Enable Conditional Access. Require MFA for all users. Disable legacy authentication. Enable PIM for privileged roles. Monitor with Microsoft Defender for Identity."},
    {"id": "cloud-k8s-rbac", "text": "Kubernetes RBAC misconfiguration: Avoid cluster-admin bindings. Use namespaced roles. Audit RBAC with kube-bench. Enable Pod Security Standards. Apply NetworkPolicies."},
]


def _get_collection():
    global _client, _collection
    if _collection is not None:
        return _collection
    if not _CHROMA_AVAILABLE:
        return None
    try:
        Path(_PERSIST_DIR).mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=_PERSIST_DIR)  # type: ignore[attr-defined]
        _collection = _client.get_or_create_collection(
            name="cosmicsec_kb",
            metadata={"hnsw:space": "cosine"},
        )
        # Ingest initial documents if collection is empty
        if _collection.count() == 0:
            _collection.add(
                ids=[doc["id"] for doc in _INITIAL_DOCUMENTS],
                documents=[doc["text"] for doc in _INITIAL_DOCUMENTS],
            )
            logger.info("ChromaDB collection initialised with %d documents", len(_INITIAL_DOCUMENTS))
        return _collection
    except Exception as exc:
        logger.warning("ChromaDB initialisation failed: %s", exc)
        return None


def chroma_search(query: str, n_results: int = 5) -> List[str]:
    """
    Semantic search over the ChromaDB knowledge collection.

    Returns a list of relevant document texts ordered by cosine similarity.
    Falls back to an empty list (caller should use TF-IDF RAG then).
    """
    collection = _get_collection()
    if collection is None:
        return []
    try:
        results = collection.query(query_texts=[query], n_results=min(n_results, collection.count()))
        docs = results.get("documents", [[]])[0]
        return [str(d) for d in docs]
    except Exception as exc:
        logger.warning("ChromaDB query failed: %s", exc)
        return []


def ingest_document(doc_id: str, text: str) -> bool:
    """Add or update a document in the ChromaDB collection. Returns True on success."""
    collection = _get_collection()
    if collection is None:
        return False
    try:
        # Upsert — update if exists, else add
        existing = collection.get(ids=[doc_id])
        if existing["ids"]:
            collection.update(ids=[doc_id], documents=[text])
        else:
            collection.add(ids=[doc_id], documents=[text])
        return True
    except Exception as exc:
        logger.warning("ChromaDB ingest failed: %s", exc)
        return False


def collection_count() -> int:
    """Return number of documents currently indexed."""
    collection = _get_collection()
    if collection is None:
        return 0
    try:
        return collection.count()
    except Exception:
        return 0
