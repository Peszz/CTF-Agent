"""
Session logger for the Kali CTF Agent.
Saves every command, output, and LLM message so you can review the full run.
"""

import json
import datetime


class AgentLogger:
    def __init__(self, log_file: str, target: str = "", domain: str = ""):
        self.log_file = log_file
        self.session = {
            "started_at": datetime.datetime.now().isoformat(),
            "target": target,
            "domain": domain,
            "events": [],
        }

    def _event(self, kind: str, data: dict):
        self.session["events"].append({
            "time": datetime.datetime.now().isoformat(),
            "type": kind,
            **data,
        })
        self.save()

    def log_command(self, command: str, result: dict):
        self._event("command", {
            "command": command,
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "exit_code": result.get("exit_code"),
        })

    def log_file_read(self, path: str, result: dict):
        self._event("file_read", {
            "path": path,
            "content": result.get("content", ""),
            "error": result.get("error"),
        })

    def log_llm_message(self, message: dict):
        self._event("llm_message", {"message": message})

    def log_tool_result(self, tool: str, summary: str):
        """Record a tool's result for tools that don't go through log_command
        (e.g. browser actions) so the post-run playbook extractor can see them."""
        self._event("tool_result", {"tool": tool, "summary": summary})

    def save(self):
        self.session["finished_at"] = datetime.datetime.now().isoformat()
        with open(self.log_file, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self.session, f, indent=2)
