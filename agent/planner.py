from __future__ import annotations

import re
from typing import Any, Callable

from agent.context import SessionContext
from agent.llm import Action, LLMClient
from agent.prompts import enumeration, flag_capture, foothold, privesc, recon
from agent.prompts.system import AVAILABLE_TOOLS, BASE_SYSTEM_PROMPT
from config import AppConfig
from db.session import SessionDB
from htb.api import HTBClient
from reporting.session_log import SessionLog
from tools.base import ToolResult
from tools.crack import CrackTools
from tools.exploit import ExploitTools
from tools.hosts import HostsManager
from tools.post import PostTools
from tools.recon import ReconTools
from tools.shell import ShellRunner
from tools.web import WebTools


PHASES = ["recon", "enumeration", "foothold", "privesc", "flag_capture"]
PHASE_PROMPTS = {
    "recon": recon.PROMPT,
    "enumeration": enumeration.PROMPT,
    "foothold": foothold.PROMPT,
    "privesc": privesc.PROMPT,
    "flag_capture": flag_capture.PROMPT,
}
FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"\b[a-f0-9]{32}\b",
]


class Planner:
    def __init__(
        self,
        config: AppConfig,
        db: SessionDB,
        llm: LLMClient,
        runner: ShellRunner,
        hosts: HostsManager,
        htb: HTBClient | None = None,
    ):
        self.config = config
        self.db = db
        self.llm = llm
        self.runner = runner
        self.hosts = hosts
        self.htb = htb
        self.phase_attempts_without_progress: dict[str, int] = {}

    def run(self, session_id: str, max_iterations: int | None = None) -> None:
        max_iterations = max_iterations or self.config.planner.max_iterations
        session = self.db.get_session(session_id)
        if not session:
            raise KeyError(f"Unknown session {session_id}")
        log = SessionLog.for_machine(self.config.paths.sessions_dir, session.machine_name, session.date)
        log.initialize(
            {
                "name": session.machine_name,
                "ip": session.machine_ip,
                "os": session.os,
                "difficulty": session.difficulty,
            }
        )

        last_observation = "No tools have run yet."
        for _ in range(max_iterations):
            session = self.db.get_session(session_id)
            if not session or session.status == "completed":
                return

            context = SessionContext.load(self.db, session_id)
            prompt = self._build_user_prompt(context, last_observation)
            action = self.llm.complete_action(BASE_SYSTEM_PROMPT, prompt)
            if action.phase != session.phase:
                action = action.model_copy(update={"phase": session.phase})

            self.db.add_reasoning_step(session_id, action.phase, action.reasoning, action.tool, action.args)
            before_score = self._progress_score(self.db.context(session_id))
            result = self.dispatch(action, session_id)
            self._persist_result(session_id, action, result)
            flags = self._detect_and_record_flags(session_id, result)
            log.append_entry(action.phase, action.reasoning, result.command, result.stdout, result.stderr, flags)

            after_context = self.db.context(session_id)
            after_score = self._progress_score(after_context)
            progressed = after_score > before_score or result.ok and action.tool in {"hosts_add", "record_credential", "record_flag"}
            last_observation = self._format_observation(result)

            if self.db.complete_session_if_flags_found(session_id):
                log.append_summary("Both required flags appear to be captured. Session marked completed.")
                return
            self._maybe_advance_phase(session_id, action.phase, after_context, progressed)

        self.db.update_status(session_id, "paused")
        log.append_summary(f"Paused after reaching max_iterations={max_iterations}.")

    def dispatch(self, action: Action, session_id: str) -> ToolResult:
        session = self.db.get_session(session_id)
        if not session:
            return ToolResult(tool=action.tool, command=None, ok=False, error="unknown_session")
        session_dir = self.config.paths.sessions_dir / session.session_key
        session_dir.mkdir(parents=True, exist_ok=True)

        recon_tools = ReconTools(self.runner, self.config.timeouts, session_dir)
        web_tools = WebTools(self.runner, self.config.timeouts, self.config.paths, session_dir, self.hosts)
        exploit_tools = ExploitTools(self.runner, self.config.timeouts, self.config.msf)
        post_tools = PostTools(self.runner, self.config.timeouts, self.config.paths)
        crack_tools = CrackTools(self.runner, self.config.timeouts, self.config.paths)

        args = action.args
        tool_map: dict[str, Callable[[], ToolResult]] = {
            "nmap_initial": lambda: recon_tools.nmap_initial(args["target"], args.get("flags")),
            "nmap_full": lambda: recon_tools.nmap_full(args["target"], args.get("flags")),
            "nmap": lambda: recon_tools.nmap_full(args["target"], args.get("flags")) if args.get("scan") == "full" else recon_tools.nmap_initial(args["target"], args.get("flags")),
            "masscan": lambda: recon_tools.masscan(args["target"], args.get("ports", "1-65535"), int(args.get("rate", 1000))),
            "curl": lambda: web_tools.curl(args["url"], args.get("flags"), args.get("method"), args.get("data")),
            "whatweb": lambda: web_tools.whatweb(args["url"]),
            "gobuster_dir": lambda: web_tools.gobuster_dir(args["url"], args.get("wordlist"), args.get("extensions")),
            "gobuster_vhost": lambda: web_tools.gobuster_vhost(args["url"], args["ip"], args.get("wordlist"), args.get("domain")),
            "gobuster": lambda: web_tools.gobuster_vhost(args["url"], args["ip"], args.get("wordlist"), args.get("domain")) if args.get("mode") == "vhost" else web_tools.gobuster_dir(args["url"], args.get("wordlist"), args.get("extensions")),
            "ffuf_dir": lambda: web_tools.ffuf_dir(args["url"], args.get("wordlist"), args.get("match_codes", "200,204,301,302,307,401,403")),
            "ffuf_vhost": lambda: web_tools.ffuf_vhost(args["url"], args["ip"], args.get("wordlist")),
            "ffuf": lambda: web_tools.ffuf_vhost(args["url"], args["ip"], args.get("wordlist")) if args.get("mode") == "vhost" else web_tools.ffuf_dir(args["url"], args.get("wordlist"), args.get("match_codes", "200,204,301,302,307,401,403")),
            "nikto": lambda: web_tools.nikto(args["host"]),
            "searchsploit": lambda: exploit_tools.searchsploit(args["query"]),
            "netcat": lambda: exploit_tools.netcat(args["host"], int(args["port"]), args.get("data"), bool(args.get("listen", False)), int(args.get("timeout", 30))),
            "linpeas": lambda: post_tools.linpeas(args.get("path")),
            "winpeas": lambda: post_tools.winpeas(args.get("path")),
            "enum_linux": lambda: post_tools.enum_linux(),
            "http_server": lambda: post_tools.start_http_server(args["directory"], int(args.get("port", 8000))),
            "john": lambda: crack_tools.john(args["hash_file"], args.get("wordlist"), args.get("format_name")),
            "hashcat": lambda: crack_tools.hashcat(args["hash_file"], int(args["mode"]), args.get("wordlist")),
            "hydra": lambda: crack_tools.hydra(args["target"], args["service"], args.get("username"), args.get("username_file"), args.get("password"), args.get("password_file"), args.get("extra")),
            "hosts_add": lambda: self._hosts_add(args["ip"], args["hostname"]),
            "record_credential": lambda: self._record_credential(session_id, args),
            "record_flag": lambda: self._record_flag(session_id, args),
            "submit_flag": lambda: self._submit_flag(session, args),
        }

        if action.tool in {"msf_search", "msf_sessions"}:
            if not self._msf_allowed(session_id):
                return ToolResult(
                    tool=action.tool,
                    command=None,
                    ok=False,
                    error="Metasploit blocked until at least one manual exploitation attempt is recorded as failed.",
                )
            if action.tool == "msf_search":
                return exploit_tools.msf_search(args["query"])
            return exploit_tools.msf_sessions()

        if action.tool not in tool_map:
            return ToolResult(tool=action.tool, command=None, ok=False, error=f"Unknown tool: {action.tool}")
        try:
            return tool_map[action.tool]()
        except KeyError as exc:
            return ToolResult(tool=action.tool, command=None, ok=False, error=f"Missing required arg: {exc}")
        except Exception as exc:
            return ToolResult(tool=action.tool, command=None, ok=False, error=str(exc), stderr=str(exc))

    def _build_user_prompt(self, context: SessionContext, last_observation: str) -> str:
        phase = context.phase
        return (
            f"{PHASE_PROMPTS.get(phase, PHASE_PROMPTS['recon'])}\n\n"
            f"{AVAILABLE_TOOLS}\n\n"
            "Current structured session context:\n"
            f"```json\n{context.to_prompt()}\n```\n\n"
            "Last tool observation:\n"
            f"```text\n{last_observation[:6000]}\n```\n\n"
            "Choose the single next action. Return JSON only."
        )

    def _persist_result(self, session_id: str, action: Action, result: ToolResult) -> None:
        self.db.add_tool_output(
            session_id,
            action.phase,
            action.tool,
            result.command,
            result.returncode,
            result.ok,
            result.timed_out,
            result.stdout,
            result.stderr,
            result.structured,
        )
        outcome = "timeout" if result.timed_out else "ok" if result.ok else f"failed: {result.error or result.returncode}"
        self.db.add_vector(session_id, action.phase, f"{action.tool} {action.args}", outcome)

        for port in result.structured.get("ports", []):
            self.db.add_port(session_id, port)
        context = self.db.context(session_id)
        ip = context.get("session", {}).get("machine_ip")
        for hostname in result.structured.get("vhosts", []):
            self.db.add_vhost(session_id, hostname, ip, action.tool)
            if ip:
                self.hosts.add_host(ip, hostname)
        for path in result.structured.get("paths", []):
            self.db.add_web_path(session_id, path.get("url"), path.get("status_code"), path.get("length"), action.tool)
        for cred in result.structured.get("credentials", []) + result.structured.get("cracked", []):
            self.db.add_credential(
                session_id,
                cred.get("username"),
                cred.get("secret") or cred.get("password"),
                cred.get("secret_type", "password"),
                cred.get("service"),
                action.tool,
            )

    def _detect_and_record_flags(self, session_id: str, result: ToolResult) -> list[str]:
        text = f"{result.stdout}\n{result.stderr}"
        flags: list[str] = []
        for pattern in FLAG_PATTERNS:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                value = match.group(0)
                if value not in flags:
                    flags.append(value)
                    self.db.add_flag(session_id, value, _infer_flag_type(text, value), result.tool)
        return flags

    def _maybe_advance_phase(self, session_id: str, phase: str, context: dict[str, Any], progressed: bool) -> None:
        if progressed:
            self.phase_attempts_without_progress[phase] = 0
        else:
            self.phase_attempts_without_progress[phase] = self.phase_attempts_without_progress.get(phase, 0) + 1

        next_phase = self._natural_next_phase(phase, context)
        if next_phase != phase:
            self.db.update_phase(session_id, next_phase)
            return

        max_attempts = self.config.planner.max_phase_attempts_without_progress
        if self.phase_attempts_without_progress.get(phase, 0) >= max_attempts:
            if phase in {"recon", "enumeration"}:
                self.db.update_phase(session_id, PHASES[min(PHASES.index(phase) + 1, len(PHASES) - 1)])
                self.phase_attempts_without_progress[phase] = 0

    def _natural_next_phase(self, phase: str, context: dict[str, Any]) -> str:
        flags = context.get("flags", [])
        flag_types = {flag.get("flag_type") for flag in flags}
        if "root" in flag_types:
            return "flag_capture"
        if phase == "recon" and context.get("ports"):
            return "enumeration"
        if phase == "foothold" and ("user" in flag_types or flags):
            return "privesc"
        if phase == "privesc" and flags:
            return "flag_capture"
        return phase

    def _progress_score(self, context: dict[str, Any]) -> int:
        return sum(
            len(context.get(key, []))
            for key in ("ports", "vhosts", "web_paths", "credentials", "flags")
        )

    def _format_observation(self, result: ToolResult) -> str:
        return (
            f"tool={result.tool} ok={result.ok} returncode={result.returncode} timed_out={result.timed_out}\n"
            f"structured={result.structured}\n"
            f"{result.concise_output()}"
        )

    def _hosts_add(self, ip: str, hostname: str) -> ToolResult:
        changed = self.hosts.add_host(ip, hostname)
        return ToolResult(
            tool="hosts_add",
            command=f"add_host {ip} {hostname}",
            ok=True,
            stdout=f"{'Added/updated' if changed else 'Already present'} {ip} {hostname}\n",
            structured={"vhosts": [hostname], "ip": ip},
        )

    def _record_credential(self, session_id: str, args: dict[str, Any]) -> ToolResult:
        self.db.add_credential(
            session_id,
            args.get("username"),
            args["secret"],
            args.get("secret_type", "password"),
            args.get("service"),
            args.get("source", "planner"),
        )
        return ToolResult(tool="record_credential", command="record_credential", ok=True, stdout="Credential recorded\n")

    def _record_flag(self, session_id: str, args: dict[str, Any]) -> ToolResult:
        self.db.add_flag(session_id, args["value"], args.get("flag_type"), args.get("source", "planner"))
        return ToolResult(tool="record_flag", command="record_flag", ok=True, stdout="Flag recorded\n")

    def _submit_flag(self, session: Any, args: dict[str, Any]) -> ToolResult:
        if not self.htb:
            return ToolResult(tool="submit_flag", command=None, ok=False, error="HTB API client unavailable")
        if not session.machine_id:
            return ToolResult(tool="submit_flag", command=None, ok=False, error="Session has no HTB machine id")
        response = self.htb.submit_flag(session.machine_id, args["flag"], args.get("flag_type"))
        self.db.mark_flag_submitted(session.id, args["flag"])
        return ToolResult(tool="submit_flag", command="HTB API flag submit", ok=True, stdout=str(response), structured=response)

    def _msf_allowed(self, session_id: str) -> bool:
        if not self.config.planner.manual_exploit_required_before_msf:
            return True
        vectors = self.db.context(session_id).get("vectors", [])
        for vector in vectors:
            name = vector.get("vector", "")
            outcome = vector.get("outcome", "")
            if not name.startswith("msf_") and "failed" in outcome:
                return True
        return False


def _infer_flag_type(text: str, flag: str) -> str | None:
    index = text.lower().find(flag.lower())
    window = text[max(0, index - 200) : index + 200].lower() if index != -1 else text.lower()
    if "root.txt" in window or "/root" in window:
        return "root"
    if "user.txt" in window or "/home" in window:
        return "user"
    return None
