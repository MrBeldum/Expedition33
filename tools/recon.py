from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from config import TimeoutConfig
from tools.base import ToolResult
from tools.shell import ShellRunner


class ReconTools:
    def __init__(self, runner: ShellRunner, timeouts: TimeoutConfig, session_dir: Path):
        self.runner = runner
        self.timeouts = timeouts
        self.session_dir = session_dir
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def nmap_initial(self, target: str, flags: list[str] | None = None) -> ToolResult:
        return self._nmap(target, "initial", flags or ["-sC", "-sV"], self.timeouts.nmap_initial)

    def nmap_full(self, target: str, flags: list[str] | None = None) -> ToolResult:
        default_flags = ["-p-", "--min-rate", "5000", "-sV"]
        return self._nmap(target, "full", flags or default_flags, self.timeouts.nmap_full)

    def masscan(self, target: str, ports: str = "1-65535", rate: int = 1000) -> ToolResult:
        output = self.session_dir / f"masscan_{_safe_name(target)}.txt"
        args = ["masscan", target, "-p", ports, "--rate", str(rate), "-oL", str(output)]
        result = self.runner.run(args, timeout=self.timeouts.nmap_full)
        stdout = result.stdout
        if output.exists():
            stdout += "\n" + output.read_text(encoding="utf-8", errors="replace")
        ports_found = []
        for line in stdout.splitlines():
            match = re.search(r"open\s+tcp\s+(\d+)\s+([0-9.]+)", line)
            if match:
                ports_found.append({"port": int(match.group(1)), "protocol": "tcp", "state": "open", "host": match.group(2)})
        return _from_shell("masscan", result, {"ports": ports_found})

    def _nmap(self, target: str, label: str, flags: list[str], timeout: int) -> ToolResult:
        safe = _safe_name(target)
        normal = self.session_dir / f"nmap_{label}_{safe}.nmap"
        xml = self.session_dir / f"nmap_{label}_{safe}.xml"
        args = ["nmap", *flags, "-oN", str(normal), "-oX", str(xml), target]
        result = self.runner.run(args, timeout=timeout)
        structured: dict[str, Any] = {"ports": [], "normal_output": str(normal), "xml_output": str(xml)}
        if xml.exists():
            structured["ports"] = parse_nmap_xml(xml)
        return _from_shell("nmap", result, structured)


def parse_nmap_xml(path: Path) -> list[dict[str, Any]]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    ports: list[dict[str, Any]] = []
    for host in root.findall("host"):
        address_el = host.find("address")
        host_addr = address_el.attrib.get("addr") if address_el is not None else None
        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.attrib.get("state") if state_el is not None else None
            if state != "open":
                continue
            service_el = port_el.find("service")
            service: dict[str, Any] = {}
            if service_el is not None:
                service = service_el.attrib
            ports.append(
                {
                    "host": host_addr,
                    "port": int(port_el.attrib["portid"]),
                    "protocol": port_el.attrib.get("protocol", "tcp"),
                    "state": state,
                    "service": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "extrainfo": service.get("extrainfo"),
                    "tunnel": service.get("tunnel"),
                }
            )
    return ports


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def _from_shell(tool: str, result: Any, structured: dict[str, Any]) -> ToolResult:
    return ToolResult(
        tool=tool,
        command=result.command,
        ok=result.ok,
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        structured=structured,
        error=result.error,
        timed_out=result.timed_out,
        duration=result.duration,
    )
