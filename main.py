from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from agent.llm import LLMClient, LLMError
from agent.planner import Planner
from config import AppConfig, ConfigError, load_config
from db.session import SessionDB, SessionRecord
from htb.api import HTBAPIError, HTBClient
from htb.models import MachineInfo
from htb.vpn import VPNManager
from reporting.writeup import WriteupGenerator
from tools.hosts import HostsManager
from tools.shell import ShellRunner


app = typer.Typer(help="Expedition33 autonomous HackTheBox agent")
console = Console()


def cli() -> None:
    app()


@app.command()
def start(
    machine_name_or_id: str = typer.Argument(..., help="HTB machine name/id or target IP"),
    machine_ip_arg: Optional[str] = typer.Argument(
        None,
        help="Optional target IP. Use this to bypass HTB API lookup: expedition33 start Planning 10.129.17.120",
    ),
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
    interactive: bool = typer.Option(False, "--interactive", help="Confirm each tool execution"),
    max_iterations: Optional[int] = typer.Option(None, help="Planner iteration limit"),
    no_vpn: bool = typer.Option(False, help="Skip VPN connectivity checks"),
    ip: Optional[str] = typer.Option(None, "--ip", help="Target IP; same as the optional second argument"),
) -> None:
    config = _load_config(config_path)
    runner = ShellRunner(sudo=True, interactive=interactive)
    hosts = HostsManager(runner=runner)
    htb = _optional_htb(config, hosts)
    machine = _resolve_start_machine(htb, machine_name_or_id, _choose_machine_ip(machine_ip_arg, ip))
    if not machine.ip:
        raise typer.BadParameter("Resolved machine does not include an IP address")
    hosts.add_host(machine.ip, f"{machine.name.lower()}.htb")
    if machine.id and htb:
        try:
            htb.play(machine.id)
        except HTBAPIError as exc:
            console.print(f"[yellow]Warning:[/yellow] failed to start/join machine via HTB API: {exc}")
    if not no_vpn:
        VPNManager(config.htb, runner, htb).ensure_connected(machine.ip)

    db = _db(config)
    session = db.create_session(machine.name, _machine_metadata(machine))
    console.print(f"Starting session {session.session_key} against {machine.name} ({machine.ip})")
    planner = _planner(config, db, runner, hosts, htb)
    planner.run(session.id, max_iterations=max_iterations)


@app.command()
def resume(
    machine_name: Optional[str] = typer.Argument(None, help="Machine name; defaults to latest incomplete"),
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
    interactive: bool = typer.Option(False, "--interactive", help="Confirm each tool execution"),
    max_iterations: Optional[int] = typer.Option(None, help="Planner iteration limit"),
    no_vpn: bool = typer.Option(False, help="Skip VPN connectivity checks"),
) -> None:
    config = _load_config(config_path)
    db = _db(config)
    session = db.get_latest_incomplete(machine_name)
    if not session:
        raise typer.BadParameter("No incomplete session found")
    runner = ShellRunner(sudo=True, interactive=interactive)
    hosts = HostsManager(runner=runner)
    htb = _optional_htb(config, hosts)
    if session.machine_ip and not no_vpn and htb:
        VPNManager(config.htb, runner, htb).ensure_connected(session.machine_ip)
    console.print(f"Resuming session {session.session_key} at phase {session.phase}")
    planner = _planner(config, db, runner, hosts, htb)
    planner.run(session.id, max_iterations=max_iterations)


@app.command("list")
def list_machines(
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
    os_filter: Optional[str] = typer.Option(None, "--os", help="linux or windows"),
    diff: Optional[str] = typer.Option(None, "--diff", help="easy, medium, hard, insane"),
    retired: bool = typer.Option(False, "--retired", help="Include/filter retired machines"),
) -> None:
    config = _load_config(config_path)
    try:
        htb = HTBClient(config.htb)
        machines = htb.list_machines(os_filter=os_filter, difficulty=diff, retired=True if retired else None)
    except HTBAPIError as exc:
        raise typer.BadParameter(str(exc)) from exc
    table = Table(title="HTB Machines")
    for column in ("ID", "Name", "OS", "Difficulty", "Retired"):
        table.add_column(column)
    for machine in machines:
        table.add_row(
            str(machine.get("id", "")),
            str(machine.get("name", "")),
            str(machine.get("os", "")),
            str(machine.get("difficulty", "")),
            str(machine.get("retired", "")),
        )
    console.print(table)


@app.command()
def submit(
    flag: str = typer.Argument(..., help="Flag value"),
    flag_type: Optional[str] = typer.Option(None, "--type", help="user or root"),
    machine_name: Optional[str] = typer.Option(None, "--machine", help="Machine name; defaults latest session"),
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
) -> None:
    config = _load_config(config_path)
    db = _db(config)
    session = db.get_latest_incomplete(machine_name) or db.latest_session(machine_name)
    if not session or not session.machine_id:
        raise typer.BadParameter("No session with HTB machine id found")
    try:
        htb = HTBClient(config.htb)
        response = htb.submit_flag(session.machine_id, flag, flag_type)
    except HTBAPIError as exc:
        raise typer.BadParameter(str(exc)) from exc
    db.add_flag(session.id, flag, flag_type, "manual_submit")
    db.mark_flag_submitted(session.id, flag)
    console.print(response)


@app.command()
def status(
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
) -> None:
    config = _load_config(config_path)
    db = _db(config)
    runner = ShellRunner(sudo=True, interactive=False)
    vpn = VPNManager(config.htb, runner, None)
    latest = db.latest_session()
    table = Table(title="Expedition33 Status")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("tun0", "up" if vpn.has_tun0() else "down")
    if latest:
        table.add_row("latest_session", latest.session_key)
        table.add_row("machine", f"{latest.machine_name} ({latest.machine_ip or 'unknown IP'})")
        table.add_row("phase", latest.phase)
        table.add_row("status", latest.status)
    else:
        table.add_row("latest_session", "none")
    console.print(table)


@app.command()
def writeup(
    machine_name: Optional[str] = typer.Argument(None, help="Machine name; defaults latest session"),
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
) -> None:
    config = _load_config(config_path)
    db = _db(config)
    session = db.latest_session(machine_name)
    if not session:
        raise typer.BadParameter("No matching session found")
    llm = _optional_llm(config)
    output = WriteupGenerator(db, llm, config.paths.writeups_dir, config.paths.sessions_dir).generate(session)
    console.print(f"Writeup saved to {output}")


@app.command()
def reset(
    machine_name_or_id: Optional[str] = typer.Argument(None, help="Machine name/id; defaults latest session"),
    config_path: Path = typer.Option(Path("config.yaml"), "--config", help="Config YAML path"),
) -> None:
    config = _load_config(config_path)
    try:
        htb = HTBClient(config.htb)
    except HTBAPIError as exc:
        raise typer.BadParameter(str(exc)) from exc
    machine_id: int | None = None
    if machine_name_or_id:
        machine = _resolve_machine(htb, machine_name_or_id)
        machine_id = machine.id
    else:
        latest = _db(config).latest_session()
        machine_id = latest.machine_id if latest else None
    if not machine_id:
        raise typer.BadParameter("No machine id available for reset")
    console.print(htb.reset(machine_id))


def _resolve_machine(htb: HTBClient, value: str) -> MachineInfo:
    if value.isdigit():
        return htb.machine(int(value))
    return htb.profile(value)


def _resolve_start_machine(
    htb: HTBClient | None,
    machine_name_or_id: str,
    machine_ip: str | None,
) -> MachineInfo:
    if machine_ip:
        _validate_htb_ip(machine_ip)
        return MachineInfo(name=_safe_machine_name(machine_name_or_id), ip=machine_ip)

    if _is_htb_ip(machine_name_or_id):
        return MachineInfo(name=f"target_{machine_name_or_id.replace('.', '_')}", ip=machine_name_or_id)

    if not htb:
        raise typer.BadParameter(
            "Starting by machine name/id requires a working HTB API token. "
            "To bypass HTB lookup, provide the IP too: expedition33 start Planning 10.129.17.120"
        )

    try:
        return _resolve_machine(htb, machine_name_or_id)
    except HTBAPIError as exc:
        raise typer.BadParameter(
            f"Could not resolve '{machine_name_or_id}' through the HTB API: {exc}\n"
            "If you already know the target IP, start with: "
            f"expedition33 start {machine_name_or_id} <10.x.x.x>"
        ) from exc


def _choose_machine_ip(machine_ip_arg: str | None, ip_option: str | None) -> str | None:
    if machine_ip_arg and ip_option and machine_ip_arg != ip_option:
        raise typer.BadParameter("Provide the target IP either as the second argument or --ip, not both")
    return machine_ip_arg or ip_option


def _is_htb_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network("10.0.0.0/8")
    except ValueError:
        return False


def _validate_htb_ip(value: str) -> None:
    if not _is_htb_ip(value):
        raise typer.BadParameter(f"Expected an HTB 10.0.0.0/8 IP, got {value}")


def _safe_machine_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in value.strip())
    return safe or "target"


def _load_config(config_path: Path) -> AppConfig:
    try:
        return load_config(config_path)
    except ConfigError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _machine_metadata(machine: MachineInfo) -> dict[str, object]:
    return {
        "id": machine.id,
        "name": machine.name,
        "ip": machine.ip,
        "os": machine.os,
        "difficulty": machine.difficulty,
        "points": machine.points,
    }


def _db(config: AppConfig) -> SessionDB:
    return SessionDB(config.paths.sessions_dir / "expedition33.sqlite3")


def _planner(
    config: AppConfig,
    db: SessionDB,
    runner: ShellRunner,
    hosts: HostsManager,
    htb: HTBClient | None,
) -> Planner:
    try:
        llm = LLMClient(config.llm)
    except LLMError as exc:
        raise typer.BadParameter(str(exc)) from exc
    return Planner(config, db, llm, runner, hosts, htb)


def _optional_llm(config: AppConfig) -> LLMClient | None:
    try:
        return LLMClient(config.llm)
    except LLMError:
        return None


def _optional_htb(config: AppConfig, hosts: HostsManager) -> HTBClient | None:
    try:
        return HTBClient(config.htb, hosts)
    except HTBAPIError:
        return None


if __name__ == "__main__":
    cli()
