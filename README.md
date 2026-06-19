# Expedition33 (WARNING!: THIS REPO IS NO LONGER MAINTAINED)

Expedition33 is a terminal-based HackTheBox pentesting agent designed for Kali Linux or ParrotOS. It runs natively on the host VM, uses direct LLM API calls for planning, executes tools through sudo-backed wrappers, persists state in SQLite, and writes a running session log plus final writeup.

`opencode` is only the environment used to launch and operate the process. Expedition33 does not call back into opencode for planning.

## Features

- Direct model-agnostic planner in `agent/llm.py`.
- OpenAI-compatible provider support for OpenAI, DeepSeek, Ollama, and similar APIs.
- Anthropic provider support.
- JSON-only planner action validation with retry and tool-use rejection.
- HTB API v4 client for machine lookup, play/reset, listing, user info, and flag submission.
- tun0/OpenVPN connectivity checks.
- SQLite session persistence keyed by machine and date.
- Sudo-by-default shell execution with timeouts and structured output capture.
- `/etc/hosts` management for machine names and discovered vhosts.
- Initial wrappers for nmap, masscan, curl, whatweb, gobuster, ffuf, nikto, searchsploit, netcat, linpeas, winpeas, john, hashcat, hydra, and MSF RPC search/session listing.
- Markdown session logs and final beginner-friendly writeup generation.

## Install

```bash
cd ~/Expedition33
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
cp config.yaml.example config.yaml
```

## Configure

Set your HTB token and LLM provider in `config.yaml` or environment variables.

OpenAI example:

```yaml
htb:
  api_token: "${HTB_API_TOKEN}"

llm:
  provider: "openai"
  model: "gpt-4o"
  api_key: "${OPENAI_API_KEY}"
  base_url: null
  max_tokens: 1024
  temperature: 0.2
```

DeepSeek or other OpenAI-compatible endpoint:

```yaml
llm:
  provider: "openai"
  model: "deepseek-chat"
  api_key: "${DEEPSEEK_API_KEY}"
  base_url: "https://api.deepseek.com"
```

Ollama:

```yaml
llm:
  provider: "ollama"
  model: "llama3.1"
  api_key: "ollama"
  base_url: "http://localhost:11434/v1"
```

Anthropic:

```yaml
llm:
  provider: "anthropic"
  model: "claude-3-5-sonnet-latest"
  api_key: "${ANTHROPIC_API_KEY}"
```

## Usage

Start a machine:

```bash
expedition33 start Planning
```

Start when you already know the target IP, bypassing HTB API machine lookup:

```bash
expedition33 start Planning 10.129.17.120
```

Start directly by IP:

```bash
expedition33 start 10.129.17.120
```

Start with confirmation before every command:

```bash
expedition33 start Planning --interactive
```

Resume the latest incomplete session:

```bash
expedition33 resume
```

Resume a specific machine:

```bash
expedition33 resume Planning
```

List machines:

```bash
expedition33 list --os linux --diff easy
```

Submit a flag manually:

```bash
expedition33 submit 0123456789abcdef0123456789abcdef --type user
```

Check status:

```bash
expedition33 status
```

Generate a writeup:

```bash
expedition33 writeup Planning
```

Reset the active/latest machine:

```bash
expedition33 reset
```

## Workflow

The planner uses a plan -> act -> observe -> revise loop across these phases:

1. Recon
2. Enumeration
3. Foothold
4. Privilege Escalation
5. Flag Capture

Each LLM response must be one JSON object:

```json
{
  "phase": "enumeration",
  "reasoning": "Port 80 is open, so I will fingerprint the web stack before fuzzing.",
  "tool": "whatweb",
  "args": {
    "url": "http://10.10.11.45/"
  }
}
```

Expedition33 validates the JSON, dispatches the named wrapper, stores parsed results in SQLite, appends the session log, then feeds the observation back to the planner.

## Files

- `sessions/expedition33.sqlite3`: SQLite session database.
- `sessions/<machine>_<date>.md`: running markdown log.
- `sessions/<session_key>/`: tool output files such as nmap XML.
- `writeups/<machine>_writeup.md`: generated final writeup.

## Notes

- All commands run through `ShellRunner` with sudo by default.
- Brute-force and cracking wrappers are capped at 5 minutes by default.
- Hydra refuses to run unless concrete username/password context is provided.
- Metasploit RPC search/session actions are blocked until a manual exploitation attempt has failed, unless disabled in config.
- The HTB VPN download endpoint may need adjustment if HTB changes its API. You can set `htb.vpn_config_path` directly to avoid API download.
