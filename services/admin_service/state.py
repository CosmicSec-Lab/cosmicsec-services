from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import os
import json
from typing import Any

STATE_PATH = Path(__file__).resolve().parent / "admin_state.json"
BACKUP_PATH = Path(__file__).resolve().parent / "admin_state_backup.json"
STORAGE_MODE = os.getenv("COSMICSEC_STORAGE_MODE", "dynamic")
_MEMORY_STATE = None


@dataclass
class AdminState:
    users: list[dict[str, Any]] = field(default_factory=list)
    roles: dict[str, str] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=lambda: {"maintenance_mode": False})
    modules: dict[str, bool] = field(
        default_factory=lambda: {
            "scan": True,
            "recon": True,
            "report": True,
            "ai": True,
        }
    )
    audit_logs: list[dict[str, Any]] = field(default_factory=list)

    def log(self, action: str, detail: str) -> None:
        self.audit_logs.append(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "action": action,
                "detail": detail,
            }
        )


def load_state() -> AdminState:
    global _MEMORY_STATE
    if STORAGE_MODE != "emergency_json":
        if _MEMORY_STATE is None:
            _MEMORY_STATE = AdminState()
        return _MEMORY_STATE

    if not STATE_PATH.exists():
        st = AdminState()
        save_state(st)
        return st
    raw = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    return AdminState(**raw)


def save_state(state: AdminState) -> None:
    global _MEMORY_STATE
    if STORAGE_MODE != "emergency_json":
        _MEMORY_STATE = state
        return
    STATE_PATH.write_text(json.dumps(state.__dict__, indent=2), encoding="utf-8")


def backup_state() -> Path:
    if STORAGE_MODE != "emergency_json":
        raise RuntimeError("Backups are available only in emergency_json mode.")
    if not STATE_PATH.exists():
        load_state()
    BACKUP_PATH.write_text(STATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return BACKUP_PATH


def restore_backup() -> bool:
    if STORAGE_MODE != "emergency_json":
        return False
    if not BACKUP_PATH.exists():
        return False
    STATE_PATH.write_text(BACKUP_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    return True
