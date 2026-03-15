"""
Phase 2 — Smart Scanning Engine.

AI-driven scan path optimisation:
- Technology fingerprinting (headers, body patterns, URL patterns)
- Priority-scored attack surface map based on detected tech stack
- Coverage-gap detection — flags scan types not yet performed
- Risk-ordered scan plan generation

The engine probes the target if httpx is available, or falls back to
URL-pattern-only fingerprinting in offline/simulation mode.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_HTTPX_AVAILABLE = False
try:
    import httpx  # type: ignore[import-not-found]
    _HTTPX_AVAILABLE = True
except Exception:
    pass

# ---------------------------------------------------------------------------
# Technology fingerprint rules
# ---------------------------------------------------------------------------

# Each rule: match_type (header|body|url), key (for headers), pattern regex,
#            tech name, attack-surface tags, risk multiplier (1.0 = normal)
_FINGERPRINTS: List[Dict[str, Any]] = [
    # ---- HTTP header-based ----
    {"match": "header", "key": "x-powered-by",  "pattern": r"php",       "tech": "PHP",            "tags": ["sqli", "lfi", "rce"],                "risk": 1.3},
    {"match": "header", "key": "x-powered-by",  "pattern": r"asp\.net",  "tech": "ASP.NET",        "tags": ["sqli", "xxe", "path_traversal"],      "risk": 1.2},
    {"match": "header", "key": "x-powered-by",  "pattern": r"express",   "tech": "Express.js",     "tags": ["xss", "sqli", "api"],                 "risk": 1.0},
    {"match": "header", "key": "server",         "pattern": r"nginx",     "tech": "Nginx",          "tags": ["misconfig", "web"],                   "risk": 0.9},
    {"match": "header", "key": "server",         "pattern": r"apache",    "tech": "Apache",         "tags": ["misconfig", "web", "lfi"],            "risk": 1.0},
    {"match": "header", "key": "server",         "pattern": r"iis",       "tech": "IIS",            "tags": ["path_traversal", "misconfig"],        "risk": 1.1},
    {"match": "header", "key": "x-generator",    "pattern": r"wordpress", "tech": "WordPress",      "tags": ["cms", "sqli", "plugin_vulns"],        "risk": 1.4},
    {"match": "header", "key": "x-drupal-cache", "pattern": r".*",        "tech": "Drupal",         "tags": ["cms", "rce", "sqli"],                 "risk": 1.3},

    # ---- Response body patterns ----
    {"match": "body", "pattern": r"wp-content|wp-admin|wp-includes",       "tech": "WordPress",      "tags": ["cms", "sqli", "plugin_vulns", "brute_force"], "risk": 1.4},
    {"match": "body", "pattern": r"Drupal\.settings|drupal\.js",           "tech": "Drupal",         "tags": ["cms", "rce"],                        "risk": 1.3},
    {"match": "body", "pattern": r"__VIEWSTATE|__EVENTTARGET",             "tech": "ASP.NET WebForms","tags": ["sqli", "path_traversal"],            "risk": 1.2},
    {"match": "body", "pattern": r"laravel_session|csrfToken.*laravel",    "tech": "Laravel",        "tags": ["sqli", "rce", "deserialization"],     "risk": 1.3},
    {"match": "body", "pattern": r"rails|csrf-token.*rails",               "tech": "Ruby on Rails",  "tags": ["sqli", "rce", "deserialization"],     "risk": 1.2},
    {"match": "body", "pattern": r"react|reactdom|__NEXT_DATA__",          "tech": "React/Next.js",  "tags": ["xss", "api"],                        "risk": 0.9},
    {"match": "body", "pattern": r"ng-version=|angular\.js",               "tech": "Angular",        "tags": ["xss", "api"],                        "risk": 0.9},
    {"match": "body", "pattern": r"swagger-ui|\"openapi\":",               "tech": "OpenAPI/Swagger", "tags": ["api", "sqli", "auth_bypass"],       "risk": 1.1},
    {"match": "body", "pattern": r"\"__schema\"|graphql",                  "tech": "GraphQL",        "tags": ["api", "introspection", "sqli"],       "risk": 1.2},
    {"match": "body", "pattern": r"jira|atlassian\.com",                   "tech": "Jira/Confluence","tags": ["ssrf", "rce", "auth_bypass"],         "risk": 1.3},

    # ---- URL pattern-based ----
    {"match": "url", "pattern": r"/wp-login|/wp-admin",                    "tech": "WordPress Admin","tags": ["brute_force", "cms"],                "risk": 1.5},
    {"match": "url", "pattern": r"/phpmyadmin",                            "tech": "phpMyAdmin",     "tags": ["sqli", "rce", "misconfig"],          "risk": 1.6},
    {"match": "url", "pattern": r"/admin|/_admin|/administrator",          "tech": "Admin Panel",    "tags": ["brute_force", "misconfig"],          "risk": 1.4},
    {"match": "url", "pattern": r"/\.git/|/\.env",                         "tech": "Source Exposure","tags": ["info_disclosure"],                   "risk": 2.0},
    {"match": "url", "pattern": r"/api/v[0-9]",                            "tech": "REST API",       "tags": ["api", "sqli", "auth_bypass"],       "risk": 1.2},
    {"match": "url", "pattern": r"/actuator|/metrics|/health",             "tech": "Spring Actuator","tags": ["info_disclosure", "rce", "ssrf"],    "risk": 1.5},
    {"match": "url", "pattern": r"/solr|/elasticsearch",                   "tech": "Search Engine",  "tags": ["rce", "info_disclosure"],            "risk": 1.5},
    {"match": "url", "pattern": r"/jenkins",                               "tech": "Jenkins",        "tags": ["rce", "auth_bypass"],                "risk": 1.6},
]

# Map attack-surface tags → canonical ScanType strings
_TAG_TO_SCAN_TYPE: Dict[str, str] = {
    "sqli":          "api",
    "rce":           "web",
    "lfi":           "web",
    "path_traversal":"web",
    "cms":           "web",
    "api":           "api",
    "brute_force":   "web",
    "xss":           "web",
    "misconfig":     "network",
    "info_disclosure":"web",
    "auth_bypass":   "api",
    "deserialization":"web",
    "ssrf":          "web",
    "introspection": "api",
    "plugin_vulns":  "web",
    "xxe":           "api",
    "cloud":         "cloud",
    "container":     "container",
}

# Base priority for each tag (0–100)
_TAG_PRIORITY: Dict[str, int] = {
    "info_disclosure": 60,
    "xss":             65,
    "brute_force":     70,
    "misconfig":       72,
    "path_traversal":  75,
    "xxe":             75,
    "ssrf":            78,
    "lfi":             78,
    "plugin_vulns":    70,
    "introspection":   60,
    "deserialization": 85,
    "auth_bypass":     85,
    "api":             80,
    "sqli":            88,
    "cms":             75,
    "rce":             95,
}


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

async def fingerprint_target(url: str) -> Dict[str, Any]:
    """
    Probe a target URL to identify its technology stack.

    Returns:
        Dict: technologies (list[str]), tags (list[str]), risk_multiplier (float), url (str)
    """
    if not _HTTPX_AVAILABLE:
        return _url_fingerprint(url)

    technologies: List[str] = []
    tags: List[str] = []
    risk_multiplier = 1.0

    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:  # type: ignore[attr-defined]
            resp = await client.get(url)
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body_snip = resp.text[:15000].lower()

            for fp in _FINGERPRINTS:
                matched = False
                if fp["match"] == "header":
                    val = headers.get(fp["key"], "")
                    matched = bool(re.search(fp["pattern"], val, re.IGNORECASE))
                elif fp["match"] == "body":
                    matched = bool(re.search(fp["pattern"], body_snip, re.IGNORECASE))

                if matched:
                    if fp["tech"] not in technologies:
                        technologies.append(fp["tech"])
                    for t in fp["tags"]:
                        if t not in tags:
                            tags.append(t)
                    risk_multiplier = max(risk_multiplier, fp["risk"])

    except Exception as exc:
        logger.debug("Fingerprint HTTP probe failed (%s): %s", url, exc)

    # Always apply URL-pattern rules
    url_result = _url_fingerprint(url)
    for t in url_result["technologies"]:
        if t not in technologies:
            technologies.append(t)
    for tg in url_result["tags"]:
        if tg not in tags:
            tags.append(tg)
    risk_multiplier = max(risk_multiplier, url_result["risk_multiplier"])

    if not tags:
        tags = ["web", "misconfig"]

    return {
        "url": url,
        "technologies": technologies,
        "tags": tags,
        "risk_multiplier": round(risk_multiplier, 2),
    }


def _url_fingerprint(url: str) -> Dict[str, Any]:
    """Static URL-pattern-only fingerprinting (no network I/O)."""
    technologies: List[str] = []
    tags: List[str] = []
    risk = 1.0

    for fp in _FINGERPRINTS:
        if fp["match"] == "url":
            if re.search(fp["pattern"], url, re.IGNORECASE):
                if fp["tech"] not in technologies:
                    technologies.append(fp["tech"])
                for t in fp["tags"]:
                    if t not in tags:
                        tags.append(t)
                risk = max(risk, fp.get("risk", 1.0))

    return {"url": url, "technologies": technologies, "tags": tags, "risk_multiplier": round(risk, 2)}


# ---------------------------------------------------------------------------
# Scan plan builder
# ---------------------------------------------------------------------------

def build_scan_plan(
    fingerprint: Dict[str, Any],
    previously_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build a prioritised scan plan from a fingerprint result.

    Args:
        fingerprint: Result from fingerprint_target().
        previously_run: List of scan_type strings already executed.

    Returns:
        Dict with scan_plan (sorted steps), coverage_gaps, risk_score.
    """
    tags = fingerprint.get("tags", ["web"])
    technologies = fingerprint.get("technologies", [])
    risk_mult = fingerprint.get("risk_multiplier", 1.0)
    already_done = set(previously_run or [])

    # Aggregate priority per scan type
    scan_scores: Dict[str, float] = {}
    rationales: Dict[str, List[str]] = {}

    for tag in tags:
        scan_type = _TAG_TO_SCAN_TYPE.get(tag, "web")
        base_prio = _TAG_PRIORITY.get(tag, 50)
        adjusted = base_prio * risk_mult
        if scan_type not in scan_scores or scan_scores[scan_type] < adjusted:
            scan_scores[scan_type] = adjusted
        rationales.setdefault(scan_type, []).append(tag)

    # Build plan
    plan = []
    for scan_type, score in sorted(scan_scores.items(), key=lambda x: -x[1]):
        already = scan_type in already_done
        plan.append({
            "scan_type": scan_type,
            "priority": round(score, 1),
            "rationale": f"Indicators: {', '.join(rationales.get(scan_type, []))}",
            "already_performed": already,
            "recommended": not already,
        })

    # Coverage gaps — scan types with high priority that haven't been done
    gaps = [s["scan_type"] for s in plan if not s["already_performed"] and s["priority"] >= 70]

    # Overall risk score (0-100)
    overall_risk = min(100, int(max(scan_scores.values(), default=50) * risk_mult))

    return {
        "target": fingerprint.get("url", ""),
        "technologies_detected": technologies,
        "scan_plan": plan,
        "recommended_first": plan[0]["scan_type"] if plan else "web",
        "coverage_gaps": gaps,
        "risk_score": overall_risk,
        "total_recommended_types": len(gaps),
    }


async def smart_scan(
    url: str,
    previously_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Full smart scan: fingerprint the target then generate a prioritised scan plan.

    Args:
        url: Target URL.
        previously_run: Scan types already executed (for coverage-gap detection).

    Returns:
        Combined fingerprint + scan plan dict.
    """
    fp = await fingerprint_target(url)
    plan = build_scan_plan(fp, previously_run)
    return {
        "url": url,
        "fingerprint": fp,
        "scan_plan": plan,
    }
