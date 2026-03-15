import os
import socket
from datetime import datetime
from urllib.parse import quote

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CosmicSec Recon Service", version="1.0.0")


class ReconRequest(BaseModel):
    target: str


def _dns_recon(target: str) -> dict:
    result: dict = {"target": target, "ips": [], "errors": []}
    try:
        _, _, ips = socket.gethostbyname_ex(target)
        result["ips"] = sorted(set(ips))
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


async def _shodan_lookup(client: httpx.AsyncClient, target: str) -> dict:
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"enabled": False, "reason": "SHODAN_API_KEY not configured"}

    url = f"https://api.shodan.io/dns/domain/{quote(target)}"
    try:
        response = await client.get(url, params={"key": api_key}, timeout=8.0)
        response.raise_for_status()
        body = response.json()
        return {
            "enabled": True,
            "subdomains": body.get("subdomains", [])[:25],
            "data_preview": body.get("data", [])[:5],
        }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}


async def _virustotal_lookup(client: httpx.AsyncClient, target: str) -> dict:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"enabled": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/domains/{quote(target)}"
    headers = {"x-apikey": api_key}
    try:
        response = await client.get(url, headers=headers, timeout=8.0)
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"enabled": True, "analysis_stats": stats}
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "recon-service"}


@app.post("/recon")
async def run_recon(payload: ReconRequest) -> dict:
    target = payload.target.strip()
    dns = _dns_recon(target)

    async with httpx.AsyncClient() as client:
        shodan = await _shodan_lookup(client, target)
        virustotal = await _virustotal_lookup(client, target)

    return {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "dns": dns,
        "shodan": shodan,
        "virustotal": virustotal,
        "findings": [
            {"source": "dns", "summary": f"Resolved addresses for {target}: {', '.join(dns['ips']) if dns['ips'] else 'none'}"},
            {"source": "osint", "summary": f"External intelligence checks completed for {target}"},
        ],
    }
