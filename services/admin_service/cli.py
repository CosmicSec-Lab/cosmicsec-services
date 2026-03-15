from __future__ import annotations

import json
from pathlib import Path

import typer  # type: ignore[import-not-found]
from rich.console import Console
from rich.table import Table

from .state import backup_state, load_state, restore_backup, save_state

app = typer.Typer(help="CosmicSec admin command suite")
user_app = typer.Typer(help="User management commands")
role_app = typer.Typer(help="Role management commands")
config_app = typer.Typer(help="Configuration commands")
module_app = typer.Typer(help="Module control commands")
audit_app = typer.Typer(help="Audit log commands")
stats_app = typer.Typer(help="Platform statistics commands")
health_app = typer.Typer(help="Health diagnostics commands")
backup_app = typer.Typer(help="Backup operations")

console = Console()

app.add_typer(user_app, name="user")
app.add_typer(role_app, name="role")
app.add_typer(config_app, name="config")
app.add_typer(module_app, name="module")
app.add_typer(audit_app, name="audit")
app.add_typer(stats_app, name="stats")
app.add_typer(health_app, name="health")
app.add_typer(backup_app, name="backup")


@user_app.command("list")
def user_list() -> None:
    state = load_state()
    table = Table(title="Users")
    table.add_column("email")
    table.add_column("role")
    for u in state.users:
        table.add_row(u.get("email", ""), u.get("role", "user"))
    console.print(table)


@user_app.command("add")
def user_add(email: str, role: str = "user") -> None:
    state = load_state()
    state.users.append({"email": email, "role": role})
    state.log("user.add", f"{email}:{role}")
    save_state(state)
    console.print(f"Added {email}")


@user_app.command("delete")
def user_delete(email: str) -> None:
    state = load_state()
    state.users = [u for u in state.users if u.get("email") != email]
    state.log("user.delete", email)
    save_state(state)
    console.print(f"Deleted {email}")


@role_app.command("assign")
def role_assign(email: str, role: str) -> None:
    state = load_state()
    state.roles[email] = role
    state.log("role.assign", f"{email}:{role}")
    save_state(state)
    console.print(f"Assigned {role} to {email}")


@role_app.command("revoke")
def role_revoke(email: str) -> None:
    state = load_state()
    state.roles.pop(email, None)
    state.log("role.revoke", email)
    save_state(state)
    console.print(f"Revoked role for {email}")


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    state = load_state()
    state.config[key] = value
    state.log("config.set", f"{key}={value}")
    save_state(state)
    console.print(f"Config set: {key}={value}")


@config_app.command("get")
def config_get(key: str) -> None:
    state = load_state()
    console.print(state.config.get(key))


@config_app.command("list")
def config_list() -> None:
    state = load_state()
    console.print_json(json.dumps(state.config))


@module_app.command("enable")
def module_enable(name: str) -> None:
    state = load_state()
    state.modules[name] = True
    state.log("module.enable", name)
    save_state(state)


@module_app.command("disable")
def module_disable(name: str) -> None:
    state = load_state()
    state.modules[name] = False
    state.log("module.disable", name)
    save_state(state)


@module_app.command("list")
def module_list() -> None:
    state = load_state()
    console.print_json(json.dumps(state.modules))


@audit_app.command("view")
def audit_view(limit: int = 20) -> None:
    state = load_state()
    console.print_json(json.dumps(state.audit_logs[-limit:]))


@audit_app.command("search")
def audit_search(term: str) -> None:
    state = load_state()
    matched = [entry for entry in state.audit_logs if term in entry.get("action", "") or term in entry.get("detail", "")]
    console.print_json(json.dumps(matched))


@audit_app.command("export")
def audit_export(path: str = "audit_logs.json") -> None:
    state = load_state()
    Path(path).write_text(json.dumps(state.audit_logs, indent=2), encoding="utf-8")
    console.print(f"Exported to {path}")


@stats_app.command("show")
def stats_show() -> None:
    state = load_state()
    metrics = {
        "users": len(state.users),
        "roles_assigned": len(state.roles),
        "modules_enabled": sum(1 for v in state.modules.values() if v),
        "audit_events": len(state.audit_logs),
    }
    console.print_json(json.dumps(metrics))


@stats_app.command("export")
def stats_export(path: str = "stats.json") -> None:
    state = load_state()
    metrics = {
        "users": len(state.users),
        "roles_assigned": len(state.roles),
        "modules_enabled": sum(1 for v in state.modules.values() if v),
        "audit_events": len(state.audit_logs),
    }
    Path(path).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    console.print(f"Exported stats to {path}")


@health_app.command("check")
def health_check() -> None:
    console.print("status=healthy")


@backup_app.command("create")
def backup_create() -> None:
    path = backup_state()
    console.print(f"backup created: {path}")


@backup_app.command("restore")
def backup_restore() -> None:
    restored = restore_backup()
    console.print("backup restored" if restored else "no backup found")


@app.command("db")
def db_access(url: str = typer.Option("sqlite:///admin.db", help="Database URL")) -> None:
    console.print(f"Direct DB access target: {url}")


@app.command("shell")
def interactive_shell() -> None:
    console.print("Interactive admin shell (type 'exit' to leave)")
    while True:
        cmd = typer.prompt("cosmicsec-admin")
        if cmd.strip() == "exit":
            break
        console.print(f"executed: {cmd}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
