"""Pytest configuration and shared fixtures for CosmicSec services tests."""

import asyncio
import os
from typing import AsyncGenerator, Generator
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci-only-not-for-production")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def pytest_addoption(parser):
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests that require external services",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as integration test")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-integration"):
        return
    skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_db_session():
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.query.return_value.filter.return_value.all.return_value = []
    session.execute.return_value.first.return_value = None
    session.execute.return_value.all.return_value = []
    session.add = MagicMock()
    session.commit = MagicMock()
    session.rollback = MagicMock()
    session.close = MagicMock()
    return session


@pytest.fixture
def mock_redis():
    client = MagicMock()
    client.ping.return_value = True
    client.get.return_value = None
    client.setex.return_value = True
    client.delete.return_value = 1
    client.exists.return_value = 0
    return client


@pytest.fixture
def test_user():
    return {
        "id": "test-user-001",
        "email": "test@cosmicsec.io",
        "full_name": "Test User",
        "hashed_password": "$2b$12$LJ3m4ys3Lk4zK3zK3zK3zO0zK3zK3zK3zK3zK3zK3zK3zK3zK3z",
        "role": "user",
        "is_active": True,
    }


@pytest.fixture
def test_admin():
    return {
        "id": "test-admin-001",
        "email": "admin@cosmicsec.io",
        "full_name": "Admin User",
        "hashed_password": "$2b$12$LJ3m4ys3Lk4zK3zK3zK3zO0zK3zK3zK3zK3zK3zK3zK3zK3zK3z",
        "role": "admin",
        "is_active": True,
    }


@pytest.fixture
def test_scan():
    return {
        "id": "test-scan-001",
        "target": "example.com",
        "scan_types": ["nmap", "nuclei"],
        "tool": "smart_scanner",
        "status": "completed",
        "progress": 100,
        "source": "web_scan",
    }


@pytest.fixture
def test_finding():
    return {
        "id": "test-finding-001",
        "scan_id": "test-scan-001",
        "title": "Open SSH Port",
        "severity": "medium",
        "description": "SSH port 22 is open",
        "evidence": "Port 22/tcp open ssh",
        "tool": "nmap",
        "target": "example.com",
        "source": "web_scan",
    }


@pytest.fixture
def sample_nmap_xml():
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV example.com" start="1700000000" version="7.94">
  <host starttime="1700000000" endtime="1700000100">
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


@pytest.fixture
def sample_nuclei_jsonl():
    return (
        '{"template":"exposed-panels/nginx.yaml","info":{"name":"Nginx Info Leak",'
        '"severity":"low","tags":["panel","nginx"]},"host":"https://example.com",'
        '"matched":"https://example.com/server-status","type":"http"}\n'
    )


@pytest.fixture
def sample_grype_json():
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "description": "Sample vulnerability",
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1",
                    "type": "deb",
                },
            }
        ],
        "source": {"target": "nginx:1.24"},
    }


@pytest.fixture
def sample_trivy_json():
    return {
        "Results": [
            {
                "Target": "nginx:1.24",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-5678",
                        "Severity": "CRITICAL",
                        "Title": "Buffer overflow in TLS handling",
                        "Description": "A buffer overflow...",
                    }
                ],
            }
        ]
    }


@pytest.fixture
def sample_semgrep_json():
    return {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "extra": {
                    "severity": "WARNING",
                    "message": "Detected use of eval()",
                    "metadata": {"owasp": ["A03:2021"]},
                },
                "path": "app/main.py",
            }
        ]
    }
