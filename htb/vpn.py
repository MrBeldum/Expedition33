from __future__ import annotations

import time
from pathlib import Path

from config import HTBConfig
from htb.api import HTBClient
from tools.shell import ShellRunner


class VPNManager:
    def __init__(self, config: HTBConfig, runner: ShellRunner, api: HTBClient | None = None):
        self.config = config
        self.runner = runner
        self.api = api

    def has_tun0(self) -> bool:
        result = self.runner.run(["ip", "-o", "addr", "show", "dev", "tun0"], timeout=10, sudo=False)
        return result.ok and "tun0" in result.stdout

    def ensure_connected(self, machine_ip: str) -> None:
        if not self.has_tun0():
            ovpn = self._resolve_ovpn()
            self.runner.start_background(["openvpn", "--config", str(ovpn)], sudo=True)
            for _ in range(20):
                if self.has_tun0():
                    break
                time.sleep(1)
        if not self.has_tun0():
            raise RuntimeError("tun0 is not active and OpenVPN did not come up")
        if not self.ping(machine_ip):
            raise RuntimeError(f"VPN is up but {machine_ip} is not reachable by ping")

    def ping(self, machine_ip: str) -> bool:
        result = self.runner.run(["ping", "-c", "1", "-W", "3", machine_ip], timeout=10, sudo=False)
        return result.ok

    def _resolve_ovpn(self) -> Path:
        if self.config.vpn_config_path and self.config.vpn_config_path.exists():
            return self.config.vpn_config_path
        if not self.api:
            raise RuntimeError("No VPN config path configured and no HTB API client available")
        return self.api.download_vpn_config(self.config.vpn_download_path)
