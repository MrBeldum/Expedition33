from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from config import PathConfig, TimeoutConfig
from tools.base import ToolResult
from tools.hosts import HostsManager
from tools.shell import ShellRunner


class WebTools:
    def __init__(
        self,
        runner: ShellRunner,
        timeouts: TimeoutConfig,
        paths: PathConfig,
        session_dir: Path,
        hosts: HostsManager | None = None,
    ):
        self.runner = runner
        self.timeouts = timeouts
        self.paths = paths
        self.session_dir = session_dir
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.hosts = hosts

    def curl(self, url: str, flags: list[str] | None = None, method: str | None = None, data: str | None = None) -> ToolResult:
        args = ["curl", "-i", "-sS", "--max-time", str(self.timeouts.curl)]
        if method:
            args.extend(["-X", method])
        if data is not None:
            args.extend(["--data", data])
        if flags:
            args.extend(flags)
        args.append(url)
        result = self.runner.run(args, timeout=self.timeouts.curl)
        structured = parse_http_response(result.stdout)
        vhosts = _extract_vhosts_from_headers(structured.get("headers", {}))
        structured["vhosts"] = vhosts
        return _from_shell("curl", result, structured)

    def whatweb(self, url: str) -> ToolResult:
        output = self.session_dir / f"whatweb_{_safe_name(url)}.json"
        args = ["whatweb", "--log-json", str(output), url]
        result = self.runner.run(args, timeout=self.timeouts.whatweb)
        structured: dict[str, Any] = {"results": []}
        if output.exists():
            try:
                structured["results"] = json.loads(output.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                structured["results"] = []
        return _from_shell("whatweb", result, structured)

    def gobuster_dir(self, url: str, wordlist: str | None = None, extensions: str | None = None) -> ToolResult:
        args = ["gobuster", "dir", "-u", url, "-w", wordlist or str(self.paths.wordlist), "--no-error"]
        if extensions:
            args.extend(["-x", extensions])
        result = self.runner.run(args, timeout=self.timeouts.gobuster)
        paths = parse_gobuster_paths(result.stdout, base_url=url)
        return _from_shell("gobuster", result, {"paths": paths})

    def gobuster_vhost(self, url: str, ip: str, wordlist: str | None = None, domain: str | None = None) -> ToolResult:
        args = ["gobuster", "vhost", "-u", url, "-w", wordlist or str(self.paths.wordlist), "--append-domain"]
        if domain:
            args.extend(["--domain", domain])
        result = self.runner.run(args, timeout=self.timeouts.gobuster)
        vhosts = parse_vhosts(result.stdout)
        for hostname in vhosts:
            if self.hosts:
                self.hosts.add_host(ip, hostname)
        return _from_shell("gobuster", result, {"vhosts": vhosts})

    def ffuf_dir(self, url: str, wordlist: str | None = None, match_codes: str = "200,204,301,302,307,401,403") -> ToolResult:
        output = self.session_dir / f"ffuf_{_safe_name(url)}.json"
        args = [
            "ffuf",
            "-u",
            url,
            "-w",
            wordlist or str(self.paths.wordlist),
            "-mc",
            match_codes,
            "-of",
            "json",
            "-o",
            str(output),
        ]
        result = self.runner.run(args, timeout=self.timeouts.ffuf)
        paths = parse_ffuf_json(output)
        return _from_shell("ffuf", result, {"paths": paths})

    def ffuf_vhost(self, url: str, ip: str, wordlist: str | None = None) -> ToolResult:
        output = self.session_dir / f"ffuf_vhost_{_safe_name(url)}.json"
        args = [
            "ffuf",
            "-u",
            url,
            "-H",
            "Host: FUZZ",
            "-w",
            wordlist or str(self.paths.wordlist),
            "-of",
            "json",
            "-o",
            str(output),
        ]
        result = self.runner.run(args, timeout=self.timeouts.ffuf)
        items = parse_ffuf_json(output)
        vhosts = [item.get("input", {}).get("FUZZ") or item.get("host") for item in items]
        vhosts = [host for host in vhosts if host]
        for hostname in vhosts:
            if self.hosts:
                self.hosts.add_host(ip, hostname)
        return _from_shell("ffuf", result, {"vhosts": vhosts})

    def nikto(self, host: str) -> ToolResult:
        args = ["nikto", "-host", host]
        result = self.runner.run(args, timeout=self.timeouts.nikto)
        findings = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("+")]
        return _from_shell("nikto", result, {"findings": findings})


def parse_http_response(text: str) -> dict[str, Any]:
    headers: dict[str, str] = {}
    status_code = None
    lines = text.splitlines()
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return {"status_code": status_code, "headers": headers}


def parse_gobuster_paths(text: str, base_url: str) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = re.search(r"^(/\S*)\s+\(Status:\s*(\d+)\).*?\[Size:\s*(\d+)\]", line.strip())
        if match:
            path, status, length = match.groups()
            paths.append({"url": base_url.rstrip("/") + path, "status_code": int(status), "length": int(length)})
    return paths


def parse_vhosts(text: str) -> list[str]:
    hosts: list[str] = []
    for line in text.splitlines():
        for pattern in (r"Found:\s+(\S+)", r"^\s*(\S+\.htb)\s+"):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                hosts.append(match.group(1).strip().lower())
    return sorted(set(hosts))


def parse_ffuf_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []
    results = data.get("results", []) if isinstance(data, dict) else []
    parsed: list[dict[str, Any]] = []
    for item in results:
        parsed.append(
            {
                "url": item.get("url"),
                "status_code": item.get("status"),
                "length": item.get("length"),
                "input": item.get("input", {}),
            }
        )
    return parsed


def _extract_vhosts_from_headers(headers: dict[str, str]) -> list[str]:
    values = [headers.get("location", ""), headers.get("server", "")]
    hosts: set[str] = set()
    for value in values:
        for match in re.finditer(r"([A-Za-z0-9.-]+\.htb)", value, re.IGNORECASE):
            hosts.add(match.group(1).lower())
    return sorted(hosts)


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
