"""
CosmicSec AI Service — Helix AI engine.

Phase 1: LangChain + TF-IDF RAG, OpenAI chain, security analysis endpoints.
Phase 2: ChromaDB vector store, MITRE ATT&CK, NL interface, autonomous agents.
"""

from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .agent import run_security_agent
from .mitre_attack import map_multiple, map_to_attack
from .prompt_templates import SUMMARY_TEMPLATE
from .rag_store import retrieve_guidance
from .vector_store import chroma_search, collection_count, ingest_document
from .anomaly_detector import batch_detect, detect_anomaly, fit_global_baseline
from .ai_agents import get_exploit_guidance, run_autonomous_agent
from .defensive_ai import DefensiveAI
from .red_team import RedTeamScope, plan_attack_chain, select_exploit_logic, validate_safety
from .zero_day_predictor import ZeroDayPredictor
from .quantum_security import decrypt_payload, encrypt_payload, hybrid_key_exchange, list_algorithms

app = FastAPI(
    title="CosmicSec AI Service",
    description="Helix AI — LangChain-powered security analysis, RAG guidance, and autonomous agents",
    version="2.0.0",
)

# Initialize Defensive AI
defensive_ai = DefensiveAI()
zero_day_predictor = ZeroDayPredictor()



class Finding(BaseModel):
    title: str
    severity: str = Field(default="medium")
    description: str = Field(default="")


class AnalyzeRequest(BaseModel):
    target: str
    findings: List[Finding] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    summary: str
    risk_score: int
    recommendations: List[str]


class AgentResponse(BaseModel):
    target: str
    strategy: str
    actions: List[str]
    rag_context: Optional[List[str]] = None


class NLQueryRequest(BaseModel):
    query: str = Field(..., description="Natural language security query")
    context: Optional[str] = Field(default=None, description="Optional additional context")


class MitreRequest(BaseModel):
    findings: List[str] = Field(..., description="List of finding titles or descriptions")


class MitreEntry(BaseModel):
    finding: str
    tactic: str
    technique_id: str
    technique_name: str
    mitigation: str


class MitreResponse(BaseModel):
    mappings: List[MitreEntry]
    total: int


class IngestRequest(BaseModel):
    doc_id: str = Field(..., description="Unique document identifier")
    text: str = Field(..., description="Document text to embed and index")



# Phase 2 — Anomaly detection models
class AnomalyDetectRequest(BaseModel):
    scan_record: dict = Field(..., description="Single scan result record to score")


class BatchAnomalyRequest(BaseModel):
    scan_records: List[dict] = Field(..., description="List of scan records; first N-1 used as baseline if not pre-fitted")


class FitBaselineRequest(BaseModel):
    historical_scans: List[dict] = Field(..., description="Historical scan records used to fit the anomaly baseline")


# Phase 2 — Autonomous agent model
class AutonomousAgentRequest(BaseModel):
    target: str = Field(..., description="Target system, URL, or domain")
    findings: List[str] = Field(default_factory=list, description="Finding title strings for analysis")
    query: Optional[str] = Field(default=None, description="Optional focused question for the agent")


# Phase 2 — Exploit guidance model
class ExploitGuidanceRequest(BaseModel):
    identifier: str = Field(..., description="CVE ID (e.g. CVE-2021-44228) or vulnerability name")


class RedTeamRequest(BaseModel):
    target: str
    authorized: bool = False
    environment: str = Field(default="lab")
    objectives: List[str] = Field(default_factory=list)


class ZeroDayTrainRequest(BaseModel):
    historical_records: List[dict] = Field(default_factory=list)


class ZeroDayForecastRequest(BaseModel):
    technology: str
    telemetry: dict = Field(default_factory=dict)


class ZeroDayPortfolioRequest(BaseModel):
    portfolio: List[dict] = Field(default_factory=list)


class QuantumKeyExchangeRequest(BaseModel):
    client_nonce: str
    server_nonce: str


class QuantumEncryptRequest(BaseModel):
    plaintext: dict
    shared_secret: str


class QuantumDecryptRequest(BaseModel):
    ciphertext: str
    mac: str
    shared_secret: str

@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "service": "ai",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_findings(payload: AnalyzeRequest) -> AnalyzeResponse:
    critical_count = sum(1 for finding in payload.findings if finding.severity.lower() == "critical")
    high_count = sum(1 for finding in payload.findings if finding.severity.lower() == "high")
    risk_score = min(100, critical_count * 35 + high_count * 20 + len(payload.findings) * 5)

    retrieved = retrieve_guidance(" ".join(f.title for f in payload.findings))
    recommendations = [
        "Prioritize remediation of critical/high severity findings first.",
        "Apply patching and validation tests before redeployment.",
        "Enable continuous scanning for this target in future runs.",
    ] + retrieved

    summary = SUMMARY_TEMPLATE.format(
        target=payload.target,
        count=len(payload.findings),
        critical=critical_count,
        high=high_count,
    )

    return AnalyzeResponse(summary=summary, risk_score=risk_score, recommendations=recommendations)


@app.post("/analyze/agent", response_model=AgentResponse)
async def analyze_with_agent(payload: AnalyzeRequest) -> AgentResponse:
    result = run_security_agent(
        target=payload.target,
        finding_titles=[f.title for f in payload.findings],
    )
    return AgentResponse(**result)


@app.post("/query")
async def natural_language_query(payload: NLQueryRequest) -> dict:
    """Natural language security query — blends ChromaDB semantic search with TF-IDF RAG."""
    combined = f"{payload.query} {payload.context or ''}".strip()
    # Phase 2: ChromaDB first, fall back to TF-IDF
    chroma_hits = chroma_search(combined, n_results=5)
    tfidf_hits = retrieve_guidance(combined, top_k=5)
    # Deduplicate: prefer ChromaDB results when available
    guidance = chroma_hits if chroma_hits else tfidf_hits
    agent_result = run_security_agent(
        target=payload.query,
        finding_titles=[],
        query=combined,
    )
    return {
        "query": payload.query,
        "response_mode": agent_result["strategy"],
        "guidance": guidance,
        "source": "chromadb" if chroma_hits else "tfidf",
        "actions": agent_result["actions"],
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/analyze/mitre", response_model=MitreResponse)
async def analyze_mitre(payload: MitreRequest) -> MitreResponse:
    """Map a list of findings to MITRE ATT&CK tactics and techniques."""
    raw_mappings = map_multiple(payload.findings)
    entries = [MitreEntry(**m) for m in raw_mappings]
    return MitreResponse(mappings=entries, total=len(entries))


@app.post("/kb/ingest")
async def kb_ingest(payload: IngestRequest) -> dict:
    """Ingest a new document into the ChromaDB knowledge base."""
    success = ingest_document(payload.doc_id, payload.text)
    return {
        "doc_id": payload.doc_id,
        "status": "indexed" if success else "fallback_unavailable",
        "collection_size": collection_count(),
    }


@app.get("/kb/stats")
async def kb_stats() -> dict:
    """Return current knowledge base statistics."""
    return {
        "chromadb_documents": collection_count(),
        "timestamp": datetime.utcnow().isoformat(),
    }


# ==========================================================================
# Phase 2 endpoints
# ==========================================================================

@app.post("/agent/autonomous")
async def autonomous_agent(payload: AutonomousAgentRequest) -> dict:
    """
    Autonomous multi-step security analysis agent.

    Uses LangChain ReAct agent with 4 tools when OPENAI_API_KEY is set.
    Falls back to deterministic 5-step pipeline (KB → MITRE → risk → recommendations).
    """
    result = run_autonomous_agent(
        target=payload.target,
        findings=payload.findings,
        query=payload.query,
    )
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


@app.post("/exploit/suggest")
async def exploit_suggest(payload: ExploitGuidanceRequest) -> dict:
    """
    Educational CVE exploit guidance for defensive security research.

    Returns attack technique overview, affected versions, and remediation.
    For authorised penetration testing and security research only.
    """
    guidance = get_exploit_guidance(payload.identifier)
    guidance["timestamp"] = datetime.utcnow().isoformat()
    return guidance


@app.post("/anomaly/fit")
async def anomaly_fit(payload: FitBaselineRequest) -> dict:
    """Fit the global anomaly detector on historical scan baseline data."""
    fit_global_baseline(payload.historical_scans)
    return {
        "status": "fitted",
        "sample_count": len(payload.historical_scans),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/anomaly/detect")
async def anomaly_detect(payload: AnomalyDetectRequest) -> dict:
    """
    Score a single scan record for anomalousness.

    Returns anomaly_score, is_anomaly, confidence, and explanation.
    """
    result = detect_anomaly(payload.scan_record)
    result["timestamp"] = datetime.utcnow().isoformat()
    return result


@app.post("/anomaly/batch")
async def anomaly_batch(payload: BatchAnomalyRequest) -> dict:
    """
    Score a batch of scan records.

    Automatically uses first N-1 records as baseline if no prior fit.
    """
    results = batch_detect(payload.scan_records)
    return {
        "results": results,
        "total": len(results),
        "anomalies_detected": sum(1 for r in results if r.get("is_anomaly")),
        "timestamp": datetime.utcnow().isoformat(),
    }



# ========================
# Phase 4: Defensive AI Endpoints
# ========================

@app.post("/defensive/remediation")
def get_remediation_guidance(vulnerability_type: str, finding: dict):
    """
    Generate AI-powered remediation guidance for a vulnerability

    Phase 4: Defensive AI - Auto-remediation suggestions
    """
    remediation = defensive_ai.suggest_remediation(vulnerability_type, finding)
    return {
        "success": True,
        "remediation": remediation,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/defensive/hardening")
def get_hardening_recommendations(system_type: str):
    """
    Generate security hardening recommendations for a system type

    Phase 4: Defensive AI - System hardening guidance
    """
    hardening = defensive_ai.generate_security_hardening(system_type)
    return {
        "success": True,
        "hardening": hardening,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/defensive/incident-response")
def generate_incident_response(vulnerability: dict):
    """
    Generate incident response plan for a vulnerability

    Phase 4: Defensive AI - Incident response automation
    """
    response_plan = defensive_ai.generate_incident_response_plan(vulnerability)
    return {
        "success": True,
        "incident_response_plan": response_plan,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/defensive/batch-remediation")
def batch_remediation(findings: List[dict]):
    """
    Generate remediation guidance for multiple findings

    Phase 4: Defensive AI - Batch remediation analysis
    """
    remediations = []
    for finding in findings:
        vuln_type = finding.get("vulnerability_type", "unknown")
        remediation = defensive_ai.suggest_remediation(vuln_type, finding)
        remediations.append(remediation)

    # Sort by priority
    remediations.sort(key=lambda x: {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3
    }.get(x.get("priority", "low"), 3))

    return {
        "success": True,
        "total_findings": len(findings),
        "remediations": remediations,
        "summary": {
            "critical": sum(1 for r in remediations if r.get("priority") == "critical"),
            "high": sum(1 for r in remediations if r.get("priority") == "high"),
            "medium": sum(1 for r in remediations if r.get("priority") == "medium"),
            "low": sum(1 for r in remediations if r.get("priority") == "low"),
            "auto_remediable": sum(1 for r in remediations if r.get("auto_remediable", False))
        },
        "timestamp": datetime.utcnow().isoformat()
    }


# ========================
# Phase 4: AI Red Team Endpoints
# ========================

@app.post("/red-team/safety-check")
def red_team_safety_check(payload: RedTeamRequest) -> dict:
    scope = RedTeamScope(
        target=payload.target,
        authorized=payload.authorized,
        environment=payload.environment,
        objectives=payload.objectives,
    )
    return {"success": True, "safety": validate_safety(scope), "timestamp": datetime.utcnow().isoformat()}


@app.post("/red-team/plan")
def red_team_plan(payload: RedTeamRequest) -> dict:
    scope = RedTeamScope(
        target=payload.target,
        authorized=payload.authorized,
        environment=payload.environment,
        objectives=payload.objectives,
    )
    return {"success": True, "result": plan_attack_chain(scope), "timestamp": datetime.utcnow().isoformat()}


@app.post("/red-team/attack-sequence")
def red_team_attack_sequence(payload: RedTeamRequest) -> dict:
    techniques = select_exploit_logic(payload.objectives)
    return {
        "success": True,
        "target": payload.target,
        "techniques": techniques,
        "mode": "defensive-simulation",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ========================
# Phase 4: Zero-Day Prediction Endpoints
# ========================

@app.post("/zero-day/train")
def zero_day_train(payload: ZeroDayTrainRequest) -> dict:
    result = zero_day_predictor.train(payload.historical_records)
    return {"success": True, "result": result, "timestamp": datetime.utcnow().isoformat()}


@app.post("/zero-day/forecast")
def zero_day_forecast(payload: ZeroDayForecastRequest) -> dict:
    forecast = zero_day_predictor.forecast(payload.technology, payload.telemetry)
    return {"success": True, "forecast": forecast, "timestamp": datetime.utcnow().isoformat()}


@app.post("/zero-day/risk-trends")
def zero_day_risk_trends(payload: ZeroDayPortfolioRequest) -> dict:
    trends = zero_day_predictor.risk_trends(payload.portfolio)
    return {"success": True, "trends": trends, "timestamp": datetime.utcnow().isoformat()}


# ========================
# Phase 4: Quantum-ready Security Endpoints
# ========================

@app.get("/quantum/algorithms")
def quantum_algorithms() -> dict:
    return {"success": True, "catalog": list_algorithms(), "timestamp": datetime.utcnow().isoformat()}


@app.post("/quantum/key-exchange")
def quantum_key_exchange(payload: QuantumKeyExchangeRequest) -> dict:
    return {
        "success": True,
        "exchange": hybrid_key_exchange(payload.client_nonce, payload.server_nonce),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/quantum/encrypt")
def quantum_encrypt(payload: QuantumEncryptRequest) -> dict:
    result = encrypt_payload(payload.plaintext, payload.shared_secret)
    return {"success": True, "encryption": result, "timestamp": datetime.utcnow().isoformat()}


@app.post("/quantum/decrypt")
def quantum_decrypt(payload: QuantumDecryptRequest) -> dict:
    plaintext = decrypt_payload(payload.ciphertext, payload.mac, payload.shared_secret)
    return {"success": True, "plaintext": plaintext, "timestamp": datetime.utcnow().isoformat()}
