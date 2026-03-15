"""Phase 4 quantum-ready security helpers (hybrid posture simulation)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime
from typing import Dict


def list_algorithms() -> Dict[str, object]:
    return {
        "algorithms": [
            {"name": "ML-KEM-768", "purpose": "key_encapsulation", "status": "planned"},
            {"name": "ML-DSA-65", "purpose": "signatures", "status": "planned"},
            {"name": "X25519+ML-KEM-Hybrid", "purpose": "key_exchange", "status": "active-hybrid"},
            {"name": "AES-256-GCM", "purpose": "data_encryption", "status": "active"},
        ],
        "generated_at": datetime.utcnow().isoformat(),
    }


def hybrid_key_exchange(client_nonce: str, server_nonce: str) -> Dict[str, str]:
    seed = f"{client_nonce}:{server_nonce}:{secrets.token_hex(16)}".encode("utf-8")
    shared_key = hashlib.sha256(seed).hexdigest()
    session_id = hashlib.sha1(seed).hexdigest()[:16]  # nosec B303 - non-security identifier only
    return {"session_id": session_id, "shared_secret": shared_key, "algorithm": "X25519+ML-KEM-Hybrid(simulated)"}


def encrypt_payload(plaintext: Dict[str, object], shared_secret: str) -> Dict[str, str]:
    payload = json.dumps(plaintext, separators=(",", ":"), sort_keys=True).encode("utf-8")
    key = bytes.fromhex(shared_secret[:64])
    stream = hashlib.sha256(key + b"stream").digest()
    ciphertext = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(payload))
    mac = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "mac": mac,
        "encrypted_at": datetime.utcnow().isoformat(),
    }


def decrypt_payload(ciphertext_b64: str, mac: str, shared_secret: str) -> Dict[str, object]:
    key = bytes.fromhex(shared_secret[:64])
    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    expected_mac = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_mac, mac):
        raise ValueError("MAC verification failed")

    stream = hashlib.sha256(key + b"stream").digest()
    plaintext = bytes(b ^ stream[i % len(stream)] for i, b in enumerate(ciphertext))
    return json.loads(plaintext.decode("utf-8"))
