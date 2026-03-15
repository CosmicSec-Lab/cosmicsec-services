from __future__ import annotations

import asyncio
import os
from pathlib import Path
from datetime import datetime

import asyncssh  # type: ignore[import-not-found]
import pyotp  # type: ignore[import-not-found]

from .state import load_state, save_state


HOST_KEY_PATH = Path(__file__).resolve().parent / "ssh_host_key"


def _ensure_host_key() -> str:
    if not HOST_KEY_PATH.exists():
        key = asyncssh.generate_private_key("ssh-rsa")
        HOST_KEY_PATH.write_text(key.export_private_key(), encoding="utf-8")
    return str(HOST_KEY_PATH)


class CosmicSecSSHServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        self.conn = conn

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        expected = os.getenv("COSMICSEC_ADMIN_PASSWORD", "cosmicsec_admin")
        return username == "admin" and password == expected

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        auth_keys_path = Path(os.getenv("COSMICSEC_AUTHORIZED_KEYS", str(Path.home() / ".ssh" / "authorized_keys")))
        if not auth_keys_path.exists() or username != "admin":
            return False
        authorized = auth_keys_path.read_text(encoding="utf-8", errors="ignore")
        return key.export_public_key().strip() in authorized

    def session_requested(self):
        return CosmicSecProcess()


class CosmicSecProcess(asyncssh.SSHServerProcess):
    def session_started(self):
        self._chan.write("CosmicSec admin shell ready. Enter `2fa <code>` before privileged commands.\n")
        self._mfa_verified = False
        state = load_state()
        state.log("ssh.session.start", datetime.utcnow().isoformat())
        save_state(state)

    def data_received(self, data, datatype):
        cmd = data.strip()
        state = load_state()
        if cmd.startswith("2fa "):
            code = cmd.split(" ", 1)[1]
            self._mfa_verified = validate_totp(code)
            self._chan.write("2FA verified\n" if self._mfa_verified else "2FA failed\n")
            state.log("ssh.2fa", f"verified={self._mfa_verified}")
            save_state(state)
            return

        if not self._mfa_verified:
            self._chan.write("2FA required. Use: 2fa <code>\n")
            return

        if cmd == "help":
            self._chan.write("commands: users, health, config, modules, logs, exit\n")
        elif cmd == "users":
            self._chan.write(f"users={len(state.users)}\n")
        elif cmd == "health":
            self._chan.write("status=healthy\n")
        elif cmd == "config":
            self._chan.write(f"config={state.config}\n")
        elif cmd == "modules":
            self._chan.write(f"modules={state.modules}\n")
        elif cmd == "logs":
            self._chan.write(f"logs={state.audit_logs[-10:]}\n")
        elif cmd == "exit":
            state.log("ssh.session.end", datetime.utcnow().isoformat())
            save_state(state)
            self.exit(0)
        else:
            self._chan.write(f"unknown command: {cmd}\n")


def validate_totp(code: str) -> bool:
    secret = os.getenv("COSMICSEC_ADMIN_TOTP_SECRET")
    if not secret:
        return code == "000000"
    return pyotp.TOTP(secret).verify(code)


async def start_ssh_server() -> None:
    await asyncssh.listen(
        "0.0.0.0",
        int(os.getenv("COSMICSEC_SSH_PORT", "2222")),
        server_factory=CosmicSecSSHServer,
        server_host_keys=[_ensure_host_key()],
        sftp_factory=asyncssh.SFTPServer,
        allow_scp=True,
    )
    await asyncio.Future()


def main() -> None:
    asyncio.run(start_ssh_server())


if __name__ == "__main__":
    main()
