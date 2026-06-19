from __future__ import annotations

import ipaddress
import tempfile
from pathlib import Path

from tools.shell import ShellRunner


class HostsManager:
    def __init__(self, hosts_path: Path = Path("/etc/hosts"), runner: ShellRunner | None = None):
        self.hosts_path = hosts_path
        self.runner = runner or ShellRunner()

    def add_host(self, ip: str, hostname: str) -> bool:
        _validate_htb_ip(ip)
        hostname = hostname.strip().lower()
        if not hostname:
            raise ValueError("Hostname cannot be empty")

        lines = self._read_lines()
        changed = False
        updated: list[str] = []
        found = False
        for line in lines:
            parsed = _parse_hosts_line(line)
            if parsed and hostname in parsed[1]:
                found = True
                if parsed[0] != ip:
                    hostnames = " ".join(parsed[1])
                    updated.append(f"{ip}\t{hostnames}\n")
                    changed = True
                else:
                    updated.append(line)
            else:
                updated.append(line)
        if not found:
            updated.append(f"{ip}\t{hostname}\n")
            changed = True
        if changed:
            self._write_lines(updated)
        return changed

    def remove_host(self, hostname: str) -> bool:
        hostname = hostname.strip().lower()
        lines = self._read_lines()
        changed = False
        updated: list[str] = []
        for line in lines:
            parsed = _parse_hosts_line(line)
            if parsed and hostname in parsed[1]:
                remaining = [name for name in parsed[1] if name != hostname]
                changed = True
                if remaining:
                    updated.append(f"{parsed[0]}\t{' '.join(remaining)}\n")
            else:
                updated.append(line)
        if changed:
            self._write_lines(updated)
        return changed

    def list_hosts(self) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for line in self._read_lines():
            parsed = _parse_hosts_line(line)
            if not parsed:
                continue
            ip, hostnames = parsed
            if ip.startswith("10.") or any(name.endswith(".htb") for name in hostnames):
                for hostname in hostnames:
                    entries.append({"ip": ip, "hostname": hostname})
        return entries

    def _read_lines(self) -> list[str]:
        if not self.hosts_path.exists():
            return []
        return self.hosts_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)

    def _write_lines(self, lines: list[str]) -> None:
        if self.hosts_path != Path("/etc/hosts"):
            self.hosts_path.write_text("".join(lines), encoding="utf-8")
            return

        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write("".join(lines))
            tmp_path = handle.name
        result = self.runner.run(["cp", tmp_path, str(self.hosts_path)], timeout=10, sudo=True)
        Path(tmp_path).unlink(missing_ok=True)
        if not result.ok:
            raise RuntimeError(f"Failed to update /etc/hosts: {result.stderr or result.error}")


def _parse_hosts_line(line: str) -> tuple[str, list[str]] | None:
    content = line.split("#", 1)[0].strip()
    if not content:
        return None
    parts = content.split()
    if len(parts) < 2:
        return None
    return parts[0], [part.lower() for part in parts[1:]]


def _validate_htb_ip(ip: str) -> None:
    address = ipaddress.ip_address(ip)
    if not address in ipaddress.ip_network("10.0.0.0/8"):
        raise ValueError(f"Expected an HTB 10.0.0.0/8 IP, got {ip}")
