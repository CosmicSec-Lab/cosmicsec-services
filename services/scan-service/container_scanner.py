"""
Phase 2 — Container Security Scanner.

Static analysis engine for:
- Kubernetes YAML manifests (security contexts, RBAC, networking, resource limits)
- Dockerfiles (anti-patterns, root user, secrets leakage, pinning)
- Runtime container inventory comparison (simulated when Docker daemon unavailable)

Does NOT require a Docker daemon — all analysis is pure static / text-based.
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime
from typing import Any, Dict, List

_YAML_AVAILABLE = False
try:
    import yaml  # type: ignore[import-not-found]
    _YAML_AVAILABLE = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_PORTS = {21, 22, 23, 25, 110, 143, 3306, 3389, 5432, 5900, 6379, 27017}
_PRIVILEGED_CMDS = re.compile(r"\b(chmod\s+777|chmod\s+-R\s+777|sudo\s+|--privileged)\b", re.IGNORECASE)
_CURL_PIPE_SHELL = re.compile(r"curl\s+.*\|\s*(ba)?sh", re.IGNORECASE)
_WGET_PIPE_SHELL = re.compile(r"wget\s+.*\|\s*(ba)?sh", re.IGNORECASE)
_HARDCODED_SECRET = re.compile(
    r"(password|passwd|secret|api_key|token|aws_secret|private_key)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    title: str,
    description: str,
    severity: str,
    recommendation: str,
    category: str = "container",
) -> Dict[str, Any]:
    return {
        "id": secrets.token_urlsafe(8),
        "title": title,
        "description": description,
        "severity": severity,
        "recommendation": recommendation,
        "category": category,
        "detected_at": datetime.utcnow().isoformat(),
    }


def _scan_result(scan_type: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    breakdown: Dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "info")
        breakdown[s] = breakdown.get(s, 0) + 1
    return {
        "scan_type": scan_type,
        "findings": findings,
        "findings_count": len(findings),
        "severity_breakdown": breakdown,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Kubernetes manifest analysis
# ---------------------------------------------------------------------------

def _check_container_security_context(
    container: Dict[str, Any], cname: str
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    sc = container.get("securityContext", {})

    if sc.get("privileged") is True:
        findings.append(_finding(
            title=f"Privileged container: {cname}",
            description="Container runs in privileged mode granting full host kernel access.",
            severity="critical",
            recommendation="Remove privileged: true. Use specific Linux capabilities with allowPrivilegeEscalation: false.",
        ))

    if sc.get("runAsUser") == 0 or sc.get("runAsRoot") is True:
        findings.append(_finding(
            title=f"Container runs as root (UID 0): {cname}",
            description="Container executes as UID 0, maximising damage from container escape.",
            severity="high",
            recommendation="Set runAsNonRoot: true and runAsUser to a non-zero UID.",
        ))

    if sc.get("allowPrivilegeEscalation") is not False and not sc.get("privileged"):
        findings.append(_finding(
            title=f"Privilege escalation not blocked: {cname}",
            description="allowPrivilegeEscalation is not explicitly set to false.",
            severity="medium",
            recommendation="Add securityContext.allowPrivilegeEscalation: false.",
        ))

    caps = sc.get("capabilities", {})
    if not caps.get("drop"):
        findings.append(_finding(
            title=f"No Linux capabilities dropped: {cname}",
            description="Container retains all default Linux capabilities.",
            severity="medium",
            recommendation="Set capabilities.drop: [ALL]; add back only required capabilities.",
        ))

    if not sc.get("readOnlyRootFilesystem"):
        findings.append(_finding(
            title=f"Writable root filesystem: {cname}",
            description="Container root filesystem is not marked read-only.",
            severity="low",
            recommendation="Set securityContext.readOnlyRootFilesystem: true. Mount writable emptyDir volumes where needed.",
        ))

    resources = container.get("resources", {})
    limits = resources.get("limits", {})
    if not limits.get("memory") or not limits.get("cpu"):
        findings.append(_finding(
            title=f"Missing resource limits: {cname}",
            description="No CPU or memory limits — container can exhaust node resources (DoS).",
            severity="medium",
            recommendation="Set resources.limits.cpu and resources.limits.memory.",
        ))

    # Liveness/readiness probe absence
    if not container.get("livenessProbe") and not container.get("readinessProbe"):
        findings.append(_finding(
            title=f"No health probes: {cname}",
            description="Container has no liveness or readiness probe configured.",
            severity="info",
            recommendation="Define livenessProbe and readinessProbe for reliable pod lifecycle management.",
        ))

    return findings


def analyze_kubernetes_manifest(manifest_yaml: str) -> Dict[str, Any]:
    """
    Analyse a Kubernetes YAML manifest string for security misconfigurations.

    Args:
        manifest_yaml: Raw YAML text (may contain multiple documents separated by ---).

    Returns:
        Scan result dict with findings and severity_breakdown.
    """
    findings: List[Dict[str, Any]] = []

    if not _YAML_AVAILABLE:
        findings.append(_finding(
            title="YAML parser unavailable",
            description="pyyaml is not installed; static manifest analysis is unavailable.",
            severity="info",
            recommendation="pip install pyyaml",
        ))
        return _scan_result("kubernetes_manifest", findings)

    try:
        docs = [d for d in yaml.safe_load_all(manifest_yaml) if isinstance(d, dict)]
    except yaml.YAMLError as exc:
        return {"error": f"Invalid YAML: {exc}", "findings": []}

    for doc in docs:
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unnamed")

        if kind in {"Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet", "Pod"}:
            pod_spec: Dict[str, Any] = doc.get("spec", {})
            if kind != "Pod":
                pod_spec = pod_spec.get("template", {}).get("spec", {})

            # Host namespace sharing
            if pod_spec.get("hostNetwork"):
                findings.append(_finding(
                    title=f"hostNetwork enabled: {name}",
                    description="Pod shares the host network namespace — exposes host network interfaces.",
                    severity="high",
                    recommendation="Remove hostNetwork: true unless absolutely required (e.g. CNI pods).",
                ))
            if pod_spec.get("hostPID"):
                findings.append(_finding(
                    title=f"hostPID enabled: {name}",
                    description="Pod shares host PID namespace — can inspect and signal host processes.",
                    severity="critical",
                    recommendation="Remove hostPID: true.",
                ))
            if pod_spec.get("hostIPC"):
                findings.append(_finding(
                    title=f"hostIPC enabled: {name}",
                    description="Pod shares host IPC namespace — can access host shared memory.",
                    severity="high",
                    recommendation="Remove hostIPC: true.",
                ))

            # Service account token
            if pod_spec.get("automountServiceAccountToken") is not False:
                findings.append(_finding(
                    title=f"Service account token auto-mounted: {name}",
                    description="Kubernetes API credentials are automatically mounted in every container.",
                    severity="medium",
                    recommendation="Set automountServiceAccountToken: false unless the pod requires API access.",
                ))

            all_containers = (
                pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
            )
            for container in all_containers:
                findings.extend(
                    _check_container_security_context(container, container.get("name", "unknown"))
                )

        elif kind == "CronJob":
            job_spec = doc.get("spec", {}).get("jobTemplate", {}).get("spec", {})
            pod_spec = job_spec.get("template", {}).get("spec", {})
            for container in pod_spec.get("containers", []):
                findings.extend(
                    _check_container_security_context(container, container.get("name", "unknown"))
                )

        elif kind in {"ClusterRole", "Role"}:
            for rule in doc.get("rules", []):
                if "*" in rule.get("resources", []) or "*" in rule.get("verbs", []):
                    findings.append(_finding(
                        title=f"Wildcard RBAC permissions: {name}",
                        description=f"Role '{name}' uses wildcard (*) resources or verbs.",
                        severity="high",
                        recommendation="Replace wildcards with explicit resource/verb lists. Apply least-privilege.",
                    ))
                # Dangerous verbs on sensitive resources
                dangerous = {"escalate", "bind", "impersonate"}
                found_dangerous = dangerous.intersection(set(rule.get("verbs", [])))
                if found_dangerous:
                    findings.append(_finding(
                        title=f"Dangerous RBAC verbs: {name}",
                        description=f"Role '{name}' grants dangerous verbs: {', '.join(found_dangerous)}.",
                        severity="critical",
                        recommendation="Remove escalate/bind/impersonate verbs unless explicitly required.",
                    ))

        elif kind == "ClusterRoleBinding" or kind == "RoleBinding":
            # Warn on cluster-admin bindings for non-system subjects
            for subject in doc.get("subjects", []):
                if subject.get("name") not in {"system:masters"} and doc.get("roleRef", {}).get("name") == "cluster-admin":
                    findings.append(_finding(
                        title=f"cluster-admin binding: {name}",
                        description=f"Subject '{subject.get('name')}' is bound to cluster-admin role.",
                        severity="critical",
                        recommendation="Grant only the minimum required RBAC permissions. Avoid cluster-admin bindings.",
                    ))

        elif kind == "Ingress":
            annotations = doc.get("metadata", {}).get("annotations", {})
            if not annotations.get("nginx.ingress.kubernetes.io/ssl-redirect") and \
               not annotations.get("kubernetes.io/tls"):
                findings.append(_finding(
                    title=f"Ingress without TLS redirect: {name}",
                    description="Ingress resource may accept plaintext HTTP traffic.",
                    severity="medium",
                    recommendation="Enable ssl-redirect annotation and configure TLS certificate.",
                ))

    return _scan_result("kubernetes_manifest", findings)


# ---------------------------------------------------------------------------
# Dockerfile static analysis
# ---------------------------------------------------------------------------

def analyze_dockerfile(dockerfile_content: str) -> Dict[str, Any]:
    """
    Analyse a Dockerfile for security anti-patterns.

    Args:
        dockerfile_content: Raw Dockerfile text content.

    Returns:
        Scan result dict with findings and severity_breakdown.
    """
    findings: List[Dict[str, Any]] = []
    lines = dockerfile_content.splitlines()
    runs_as_root = True
    has_healthcheck = False
    base_image_pinned = True

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        instruction, _, rest = line.partition(" ")
        instruction = instruction.upper()
        rest = rest.strip()

        if instruction == "USER":
            if rest.split()[0] not in {"root", "0"}:
                runs_as_root = False

        elif instruction == "HEALTHCHECK":
            has_healthcheck = True

        elif instruction == "FROM":
            img = rest.split()[0].lower()
            as_match = re.search(r"\s+as\s+", img)
            img_clean = img.split(" ")[0]
            if ":" not in img_clean and "@" not in img_clean:
                base_image_pinned = False
                findings.append(_finding(
                    title=f"Unpinned base image (line {idx})",
                    description=f"Base image '{img_clean}' has no version tag or digest — builds are non-reproducible.",
                    severity="medium",
                    recommendation="Pin base images: use 'image:tag' or 'image@sha256:...' for reproducible builds.",
                ))
            elif ":latest" in img_clean:
                base_image_pinned = False
                findings.append(_finding(
                    title=f"Base image pinned to :latest (line {idx})",
                    description=f"Using ':latest' tag means base image can change silently between builds.",
                    severity="medium",
                    recommendation="Pin to a specific version tag or digest.",
                ))

        elif instruction == "ENV" or instruction == "ARG":
            if _HARDCODED_SECRET.search(rest):
                findings.append(_finding(
                    title=f"Potential hardcoded secret in {instruction} (line {idx})",
                    description=f"Pattern matching a secret detected: {rest[:80]}",
                    severity="critical",
                    recommendation="Never bake secrets into images. Use Docker secrets, environment variables at runtime, or a secrets manager.",
                ))

        elif instruction == "EXPOSE":
            for token in rest.split():
                try:
                    port = int(token.split("/")[0])
                    if port in _SENSITIVE_PORTS:
                        findings.append(_finding(
                            title=f"Sensitive port exposed: {port} (line {idx})",
                            description=f"Port {port} is typically used by sensitive services.",
                            severity="medium",
                            recommendation="Avoid exposing management/database ports. Restrict to application ports only.",
                        ))
                except ValueError:
                    pass

        elif instruction == "RUN":
            if _CURL_PIPE_SHELL.search(rest) or _WGET_PIPE_SHELL.search(rest):
                findings.append(_finding(
                    title=f"Shell pipe install anti-pattern (line {idx})",
                    description="Piping remote script into (ba)sh is a supply-chain risk.",
                    severity="high",
                    recommendation="Download, verify checksum, then execute. Prefer distribution package managers.",
                ))
            if _PRIVILEGED_CMDS.search(rest):
                findings.append(_finding(
                    title=f"Dangerous RUN command (line {idx})",
                    description=f"Detected privilege-granting command: {rest[:80]}",
                    severity="high",
                    recommendation="Avoid chmod 777 or sudo in Dockerfiles. Use minimal permissions.",
                ))
            # Check for package cache not cleaned in same RUN layer
            if re.search(r"\bapt-get\s+install\b", rest) and "rm -rf /var/lib/apt/lists" not in rest:
                findings.append(_finding(
                    title=f"APT cache not cleaned (line {idx})",
                    description="apt-get install without cleaning cache increases image size and surface area.",
                    severity="info",
                    recommendation="Add '&& rm -rf /var/lib/apt/lists/*' in the same RUN layer.",
                ))

        elif instruction == "ADD":
            if rest.startswith("http://") or rest.startswith("https://"):
                findings.append(_finding(
                    title=f"ADD with remote URL (line {idx})",
                    description="ADD from a URL downloads content without checksum verification.",
                    severity="medium",
                    recommendation="Use COPY with locally verified files or RUN curl with checksum validation.",
                ))

    if runs_as_root:
        findings.append(_finding(
            title="Container runs as root user",
            description="No USER instruction found — container defaults to UID 0 (root).",
            severity="high",
            recommendation="Add 'USER <non-root-uid>' before the final CMD/ENTRYPOINT instruction.",
        ))

    if not has_healthcheck:
        findings.append(_finding(
            title="No HEALTHCHECK instruction",
            description="Container lacks a HEALTHCHECK — orchestrators cannot detect unhealthy states.",
            severity="info",
            recommendation="Add HEALTHCHECK instruction to enable orchestrator health management.",
        ))

    return _scan_result("dockerfile", findings)


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------

def scan_container_artifact(
    artifact_type: str,
    content: str,
) -> Dict[str, Any]:
    """
    Unified entry point for container security scanning.

    Args:
        artifact_type: 'dockerfile' | 'kubernetes' | 'k8s'
        content: Raw text content of the artifact.

    Returns:
        Scan result dict.
    """
    if artifact_type.lower() in {"kubernetes", "k8s", "manifest"}:
        return analyze_kubernetes_manifest(content)
    elif artifact_type.lower() in {"dockerfile", "docker"}:
        return analyze_dockerfile(content)
    else:
        return {
            "error": f"Unknown artifact_type '{artifact_type}'. Use 'dockerfile' or 'kubernetes'.",
            "findings": [],
        }
