import os
import socket
from datetime import datetime
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CosmicSec Recon Service", version="1.0.0")


class ReconRequest(BaseModel):
    target: str


def _normalize_target(target: str) -> str:
    value = target.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    return value


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


async def _crtsh_lookup(client: httpx.AsyncClient, target: str) -> dict:
    """Legacy-inspired subdomain discovery using certificate transparency logs."""
    url = "https://crt.sh/"
    try:
        response = await client.get(url, params={"q": f"%.{target}", "output": "json"}, timeout=8.0)
        response.raise_for_status()
        rows = response.json()
        names = set()
        for row in rows[:200]:
            value = row.get("name_value", "")
            for name in str(value).splitlines():
                clean = name.strip().lower().lstrip("*.")
                if clean and clean.endswith(target.lower()):
                    names.add(clean)
        return {"enabled": True, "subdomains": sorted(names)[:50]}
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}


async def _rdap_lookup(client: httpx.AsyncClient, target: str) -> dict:
    """Modern WHOIS-style metadata via RDAP without extra dependencies."""
    try:
        response = await client.get(f"https://rdap.org/domain/{quote(target)}", timeout=8.0)
        response.raise_for_status()
        body = response.json()
        events = body.get("events", [])
        nameservers = [ns.get("ldhName") for ns in body.get("nameservers", []) if ns.get("ldhName")]
        return {
            "enabled": True,
            "handle": body.get("handle"),
            "status": body.get("status", []),
            "events_preview": events[:3],
            "nameservers": nameservers[:10],
        }
    except Exception as exc:
        return {"enabled": True, "error": str(exc)}


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "recon-service"}


@app.post("/recon")
async def run_recon(payload: ReconRequest) -> dict:
    target = _normalize_target(payload.target)
    dns = _dns_recon(target)

    async with httpx.AsyncClient() as client:
        shodan = await _shodan_lookup(client, target)
        virustotal = await _virustotal_lookup(client, target)
        crtsh = await _crtsh_lookup(client, target)
        rdap = await _rdap_lookup(client, target)

    return {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "dns": dns,
        "shodan": shodan,
        "virustotal": virustotal,
        "crtsh": crtsh,
        "rdap": rdap,
        "findings": [
            {"source": "dns", "summary": f"Resolved addresses for {target}: {', '.join(dns['ips']) if dns['ips'] else 'none'}"},
            {"source": "osint", "summary": f"External intelligence checks completed for {target}"},
            {"source": "legacy-merge", "summary": "Merged legacy CT-log and WHOIS-style domain intelligence into hybrid recon flow."},
        ],
    }
