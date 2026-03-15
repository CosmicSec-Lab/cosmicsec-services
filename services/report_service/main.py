from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CosmicSec Report Service", version="1.0.0")


class ReportRequest(BaseModel):
    scan_id: str
    format: str = "pdf"


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "report-service"}


@app.post("/reports/generate")
def generate_report(payload: ReportRequest) -> dict:
    # Placeholder for PDF/DOCX rendering pipelines
    safe_format = payload.format.lower()
    if safe_format not in {"pdf", "docx"}:
        safe_format = "pdf"

    return {
        "scan_id": payload.scan_id,
        "format": safe_format,
        "artifact": f"/tmp/reports/{payload.scan_id}.{safe_format}",
        "status": "generated",
    }
