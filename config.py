from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            return os.environ.get(match.group(1), "")

        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    return value


class LLMConfig(BaseModel):
    provider: Literal["openai", "anthropic", "ollama"] = "openai"
    model: str = "gpt-4o"
    api_key: str | None = None
    base_url: str | None = None
    max_tokens: int = 1024
    temperature: float = 0.2

    @field_validator("api_key", "base_url", mode="before")
    @classmethod
    def empty_to_none(cls, value: Any) -> Any:
        if value == "":
            return None
        return value


class HTBConfig(BaseModel):
    api_token: str | None = None
    base_url: str = "https://app.hackthebox.com/api/v4"
    vpn_config_path: Path | None = None
    vpn_download_path: Path = Path("./sessions/htb.ovpn")

    @field_validator("api_token", mode="before")
    @classmethod
    def token_from_env(cls, value: Any) -> Any:
        return value or os.environ.get("HTB_API_TOKEN")


class PathConfig(BaseModel):
    sessions_dir: Path = Path("./sessions")
    writeups_dir: Path = Path("./writeups")
    wordlist: Path = Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    seclists_dir: Path = Path("/usr/share/seclists")
    rockyou: Path = Path("/usr/share/wordlists/rockyou.txt")
    linpeas: Path = Path("/opt/PEASS-ng/linPEAS/linpeas.sh")
    winpeas: Path = Path("/opt/PEASS-ng/winPEAS/winPEASx64.exe")


class TimeoutConfig(BaseModel):
    nmap_initial: int = 300
    nmap_full: int = 900
    gobuster: int = 300
    ffuf: int = 300
    nikto: int = 300
    searchsploit: int = 30
    linpeas: int = 180
    winpeas: int = 180
    john: int = 300
    hashcat: int = 300
    hydra: int = 300
    curl: int = 30
    whatweb: int = 30
    shell_default: int = 120


class PlannerConfig(BaseModel):
    max_iterations: int = 40
    max_phase_attempts_without_progress: int = 5
    manual_exploit_required_before_msf: bool = True


class MSFConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 55552
    username: str = "msf"
    password: str = "expedition33"
    ssl: bool = False


class AppConfig(BaseModel):
    htb: HTBConfig = Field(default_factory=HTBConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    paths: PathConfig = Field(default_factory=PathConfig)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    planner: PlannerConfig = Field(default_factory=PlannerConfig)
    msf: MSFConfig = Field(default_factory=MSFConfig)

    def ensure_directories(self) -> None:
        self.paths.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.paths.writeups_dir.mkdir(parents=True, exist_ok=True)


def load_config(path: str | Path = "config.yaml") -> AppConfig:
    config_path = Path(path)
    data: dict[str, Any] = {}
    if config_path.exists():
        raw = yaml.safe_load(config_path.read_text()) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"Config file {config_path} must contain a YAML mapping")
        data = _expand_env(raw)

    config = AppConfig.model_validate(data)
    if config.llm.provider == "openai" and not config.llm.api_key:
        config.llm.api_key = os.environ.get("OPENAI_API_KEY")
    if config.llm.provider == "anthropic" and not config.llm.api_key:
        config.llm.api_key = os.environ.get("ANTHROPIC_API_KEY")
    if config.llm.provider == "ollama":
        config.llm.base_url = config.llm.base_url or "http://localhost:11434/v1"
        config.llm.api_key = config.llm.api_key or "ollama"

    config.ensure_directories()
    return config
