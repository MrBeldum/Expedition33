from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from config import HTBConfig
from htb.models import MachineInfo, UserInfo
from tools.hosts import HostsManager


class HTBAPIError(RuntimeError):
    """Raised for HTB API request and response failures."""


class HTBClient:
    def __init__(self, config: HTBConfig, hosts: HostsManager | None = None):
        if not config.api_token:
            raise HTBAPIError("Missing HTB API token. Set htb.api_token or HTB_API_TOKEN.")
        self.config = config
        self.hosts = hosts
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {config.api_token}",
                "Accept": "application/json",
                "User-Agent": "Expedition33/0.1",
            }
        )

    def active_machine(self) -> dict[str, Any]:
        return self._request("GET", "/machine/active")

    def machine(self, machine_id: int) -> MachineInfo:
        machine = MachineInfo.from_api(self._request("GET", f"/machine/{machine_id}"))
        self._add_machine_host(machine)
        return machine

    def profile(self, name: str) -> MachineInfo:
        machine = MachineInfo.from_api(self._request("GET", f"/machine/profile/{name}"))
        self._add_machine_host(machine)
        return machine

    def play(self, machine_id: int) -> dict[str, Any]:
        return self._request("POST", "/machine/play", json={"machine_id": machine_id})

    def reset(self, machine_id: int) -> dict[str, Any]:
        return self._request("POST", "/machine/reset", json={"machine_id": machine_id})

    def submit_flag(self, machine_id: int, flag: str, flag_type: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"flag": flag}
        if flag_type:
            body["type"] = flag_type
        return self._request("POST", f"/machine/{machine_id}/flag", json=body)

    def list_machines(
        self,
        os_filter: str | None = None,
        difficulty: str | None = None,
        retired: bool | None = None,
    ) -> list[dict[str, Any]]:
        data = self._request("GET", "/machine/list")
        machines = data.get("data") or data.get("machines") or data
        if not isinstance(machines, list):
            raise HTBAPIError("Unexpected /machine/list response")
        filtered = machines
        if os_filter:
            filtered = [m for m in filtered if str(m.get("os", "")).lower() == os_filter.lower()]
        if difficulty:
            filtered = [m for m in filtered if str(m.get("difficulty", "")).lower() == difficulty.lower()]
        if retired is not None:
            filtered = [m for m in filtered if bool(m.get("retired")) is retired]
        return filtered

    def user_info(self) -> UserInfo:
        return UserInfo.model_validate(self._request("GET", "/user/info").get("info", {}))

    def download_vpn_config(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        response = self.session.get(f"{self.config.base_url.rstrip('/')}/connections/vpn", timeout=60)
        if response.status_code >= 400:
            raise HTBAPIError(
                f"Failed to download VPN config: HTTP {response.status_code} {_response_summary(response)}"
            )
        destination.write_bytes(response.content)
        return destination

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self.config.base_url.rstrip('/')}/{path.lstrip('/')}"
        response = self.session.request(method, url, timeout=60, **kwargs)
        if response.status_code >= 400:
            raise HTBAPIError(
                f"HTB API {method} {path} failed: HTTP {response.status_code} {_response_summary(response)}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise HTBAPIError(
                f"HTB API {method} {path} returned non-JSON: {_response_summary(response)}"
            ) from exc
        return data

    def _add_machine_host(self, machine: MachineInfo) -> None:
        if not self.hosts or not machine.ip:
            return
        self.hosts.add_host(machine.ip, f"{machine.name.lower()}.htb")


def _response_summary(response: requests.Response) -> str:
    content_type = response.headers.get("content-type", "unknown")
    location = response.headers.get("location")
    text = response.text.strip().replace("\n", " ").replace("\r", " ")
    snippet = text[:300] if text else "<empty body>"
    parts = [f"content-type={content_type!r}"]
    if location:
        parts.append(f"location={location!r}")
    parts.append(f"body={snippet!r}")
    return ", ".join(parts)
