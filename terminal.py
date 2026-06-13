"""
Persistent terminal session over SSH.

Holds ONE long-lived interactive shell on the Kali VM (paramiko invoke_shell).
Unlike one-shot exec, this behaves like a real terminal a human would use:
  - start a long scan, walk away, check back on it
  - see live/partial output while a command is still running
  - send Ctrl-C to a stuck command
  - drive interactive tools (msfconsole, ssh, sqlmap prompts)

Completion detection uses a per-command marker appended after the command.
The marker is split so the *typed* command line can't be mistaken for the
*executed* result (validated against edge cases). When the joined marker plus
exit code appears in the buffer, the command is finished; otherwise it is still
running — a truthful running-vs-done signal with no prompt guessing.
"""

import re
import time
import uuid


# ── scan/trace noise lines ───────────────────────────────────────────────────
# nmap packet-trace (SENT/RCVD), NSE/NSOCK/CONN connection traces and "Packet Tracing" headers
# flood the buffer hundreds of lines at a time and bury real output. Shared by BOTH terminal
# backends (terminal.Terminal._clean and tmux_terminal.TmuxTerminal._clean_output) so the filter
# can never drift between them again. Anchored at line start; only ever matches trace spam, never
# real command output or file content.
_SCAN_NOISE_RE = re.compile(
    r"^(NSOCK|SENT|RCVD|NSE:|CONN|Packet Tracing).*\n?", re.MULTILINE
)


# ── interactive-prompt detection ─────────────────────────────────────────────
# The marker contract (printf a sentinel after the command) ONLY works in bash. Inside any other
# REPL — meterpreter, smb:\>, mysql>, a target reverse shell, python>>> — the printf is eaten by
# the child and the marker never returns, so a marker-only reader waits forever and the model goes
# blind. The general fix is to read the way a human does: notice the output has gone quiet AND the
# tail looks like a prompt waiting for input. These two regexes classify the tail.
#
# _KNOWN_PROMPT — high confidence: a recognised REPL/shell prompt shape. Detected after a SHORT
# quiet window so we flip to interactive driving fast. Note it matches PROMPT SHAPES (generic over
# tools: any `user@host:path$`, any `>>>`, etc.), not a hardcoded list of commands.
_KNOWN_PROMPT = re.compile(
    r"(?:"
    r"meterpreter\s*>|"
    r"msf\d*\b[^>\n]*>|"
    r"smb:\s*\\[^>\n]*>|"
    r"(?:mysql|mariadb|sqlite\d*|redis[^>\n]*|mongo[^>\n]*)\s*>|"
    r"ftp>|sftp>|"
    r">>>|"                                     # python REPL prompt (bare >>>)
    r"\(pdb\)|\([^)\n]{0,24}\)\s*>|"            # (Pdb)  /  (remote) >
    r"[\w.\-]+@[\w.\-]+:[^\n]*[#$]|"            # user@host:path$  — any unix shell (incl. target)
    r"PS\s+[A-Za-z]:\\[^\n]*>"                  # Windows PowerShell
    r")[ \t]*$",
    re.MULTILINE | re.IGNORECASE,
)
# _ANY_PROMPT — looser: a short last line ending in a shell sigil. Only consulted after a FULL idle
# timeout, so a command that merely paused mid-run isn't mistaken for a prompt. Catches exotic REPLs
# whose exact prompt we don't enumerate, so the model is shown a driveable screen rather than a
# permanent blind "still running".
_ANY_PROMPT = re.compile(r"(?:^|\n)[^\n]{0,100}[#$%>][ \t]*$")


class Terminal:
    def __init__(self, ssh_client, width=220, height=50):
        self.client = ssh_client
        self.chan = ssh_client.invoke_shell(width=width, height=height)
        self.chan.settimeout(0.0)  # non-blocking reads
        self.buf = ""
        self.marker = None
        self.last_cmd = ""
        self.cmd_start = time.time()
        self._last_output_len = 0
        # "bash"  → marker-based completion (reliable, used for normal commands).
        # "interactive" → we are inside a REPL/child; drive by output quiescence and show the live
        # screen every turn. Flipped automatically when a prompt is detected, and back on exit.
        self.mode = "bash"
        time.sleep(0.4)
        self._drain(0.4)
        # Quiet the prompt noise and disable echo coloring weirdness
        self._raw_send("export PS1='' ; stty -echo 2>/dev/null ; unalias -a 2>/dev/null ; clear\n")
        time.sleep(0.3)
        self._drain(0.3)
        self.buf = ""

    # ── low level ────────────────────────────────────────────────
    def _raw_send(self, data: str):
        self.chan.send(data)

    def _drain(self, timeout=0.3) -> str:
        end = time.time() + timeout
        while time.time() < end:
            if self.chan.recv_ready():
                try:
                    self.buf += self.chan.recv(65536).decode("utf-8", "replace")
                except Exception:
                    break
            else:
                time.sleep(0.05)
        return self.buf

    @staticmethod
    def _clean(text: str) -> str:
        """Universally-safe cleanup applied to ALL terminal output AND file reads:
        strip ANSI, CR, null bytes, and nmap packet/NSE trace lines. Must NOT remove
        anything that could be meaningful file content — runtime-only noise (Python
        warning spam) is handled separately in read(), so read_file keeps source intact."""
        text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
        text = re.sub(r"\x1b\][^\x07]*\x07", "", text)
        text = text.replace("\r", "")
        # strip nmap packet-trace / NSE / connection trace lines that flood the buffer
        text = _SCAN_NOISE_RE.sub("", text)
        text = text.replace("\x00", "")
        return text

    @staticmethod
    def _strip_runtime_warnings(text: str) -> str:
        """Strip Python warning spam (urllib3 InsecureRequestWarning etc.) from LIVE command
        output only — model-written exploit scripts using verify=False emit these on every
        request, burying real output. Applied in read(), NOT in _clean, so reading a source
        file via read_file never loses a genuine `warnings.warn(...)` line.

        Both patterns match the runtime warning FORMAT (a `path:line: XxxWarning:` header and
        its bare `warnings.warn(` echo), which does not occur in normal command output —
        nmap's "Warning:" lines have no `:linenum:` prefix, so they are kept."""
        text = re.sub(r"^.*:\d+:\s+\w*Warning:.*\n?", "", text, flags=re.MULTILINE)
        text = re.sub(r"^\s*warnings\.warn\(\s*\)?\s*\n?", "", text, flags=re.MULTILINE)
        return text

    # ── public API ───────────────────────────────────────────────
    def send(self, command: str):
        """Type a command into the shell and arm completion detection."""
        tok = uuid.uuid4().hex[:10]
        self.marker = f"MK{tok}END"
        self.last_cmd = command
        # printf joins the two pieces only at execution time, so the echoed
        # input line (if any) can't false-trigger completion.
        mark = f"printf '%s%s' 'MK{tok}' 'END'$? ; printf '\\n'"
        # FOLD the marker onto the command's line for single-line foreground commands so it is not
        # left as typeahead the command can eat: nmap reads stdin during a scan (runtime keypress
        # interaction) and a REPL reads stdin too, so a marker queued on the NEXT line gets consumed
        # — the marker never returns (command looks stuck) and a REPL gets the marker typed into it.
        # On one line bash reads command+marker before the command runs. Multiline/heredoc and
        # backgrounded commands keep the marker on its own line (heredoc bodies aren't typeahead; a
        # '&' command returns to the prompt at once).
        stripped = command.rstrip()
        if "\n" not in stripped and not (stripped.endswith("&") and not stripped.endswith("&&")):
            full = f"{stripped.rstrip(';').rstrip()} ; {mark}\n"
        else:
            full = f"{command}\n{mark}\n"
        self.buf = ""
        self.cmd_start = time.time()
        self._last_output_len = 0
        self._raw_send(full)

    def read(self, wait=0.6) -> dict:
        """Poll the terminal.

        Returns dict:
          output       — output so far (partial if running)
          running      — True if command still executing
          exit_code    — command status once finished (else None)
          elapsed_seconds — wall-clock since the command started
          output_lines    — number of output lines so far
          new_since_last_check — output lines produced since the previous read()
        """
        self._drain(wait)
        clean = self._strip_runtime_warnings(self._clean(self.buf))
        elapsed = round(time.time() - self.cmd_start, 1)
        m = re.search(re.escape(self.marker) + r"(\d+)", clean) if self.marker else None

        if m:
            output = self._strip_echo(clean[:m.start()]).strip("\n")
            lines = output.count("\n") + 1 if output else 0
            new = max(0, lines - self._last_output_len)
            self._last_output_len = lines
            return {
                "output": output,
                "running": False,
                "exit_code": int(m.group(1)),
                "elapsed_seconds": elapsed,
                "output_lines": lines,
                "new_since_last_check": new,
            }

        # No marker set means no command is active (startup state or after interrupt()).
        # Return running=False so callers don't spin waiting for a marker that never comes.
        if not self.marker:
            output = self._strip_echo(clean)
            lines = output.count("\n") + 1 if output.strip() else 0
            return {
                "output": output,
                "running": False,
                "exit_code": None,
                "elapsed_seconds": elapsed,
                "output_lines": lines,
                "new_since_last_check": 0,
            }

        output = self._strip_echo(clean)
        lines = output.count("\n") + 1 if output.strip() else 0
        new = max(0, lines - self._last_output_len)
        self._last_output_len = lines
        return {
            "output": output,
            "running": True,
            "exit_code": None,
            "elapsed_seconds": elapsed,
            "output_lines": lines,
            "new_since_last_check": new,
        }

    def _strip_echo(self, text: str) -> str:
        """Remove the echoed command line and the printf marker line, plus any executed marker token.
        The token is stripped by its fixed SHAPE (MK<10hex>END<exit>) not the active marker, so the
        folded END marker that prints once a driven REPL exits — by which point self.marker is None —
        is still removed rather than shown as garbage."""
        lines = text.split("\n")
        cleaned = []
        for ln in lines:
            if self.last_cmd and ln.strip() == self.last_cmd.strip():
                continue
            if "printf '%s%s'" in ln:                      # echoed marker printf (folded or standalone)
                continue
            ln = re.sub(r"MK[0-9a-f]{10}END\d*", "", ln)   # executed marker token, by shape
            cleaned.append(ln)
        return "\n".join(cleaned)

    @staticmethod
    def _prompt_tail(text: str, loose: bool = False) -> str:
        """Return the matched prompt string if the tail of `text` looks like an interactive prompt
        waiting for input, else ''. `loose` also accepts a generic shell-sigil last line."""
        tail = text[-400:]
        m = _KNOWN_PROMPT.search(tail)
        if m:
            return m.group().strip()
        if loose:
            m = _ANY_PROMPT.search(tail)
            if m:
                return m.group().strip()
        return ""

    def wait(self, max_wait=600, idle_wait=30, poll=0.6, prompt_quiesce=1.2) -> dict:
        """Block until the current command finishes, lands at an interactive prompt, or times out.

        Three outcomes (whichever happens first):
          marker found            → running=False (command completed in bash; exit_code set).
          idle at a prompt        → running=False, awaiting_input=True (a REPL/child is waiting for
                                     input). Detected fast (after `prompt_quiesce`s of quiet) for a
                                     KNOWN prompt shape; or at the full idle timeout for a loose one.
                                     This is what stops the model going blind in a REPL: instead of a
                                     marker that never comes, it gets the live screen + "your move".
          idle / hard timeout     → running=True (a genuinely long command still computing).
            idle_wait  — seconds of no new output (resets on new output) before giving up.
            max_wait   — absolute wall-clock cap.
        """
        hard_deadline = time.time() + max_wait
        idle_deadline = time.time() + idle_wait
        last_change = time.time()
        last = {"output": "", "running": True, "exit_code": None}

        while time.time() < hard_deadline:
            last = self.read(wait=poll)
            if not last["running"]:
                return last  # marker → command completed in bash

            if last.get("new_since_last_check", 0) > 0:
                idle_deadline = time.time() + idle_wait
                last_change = time.time()

            quiet_for = time.time() - last_change
            # Fast path: gone quiet at a recognised prompt ⇒ a REPL is waiting for input.
            if quiet_for >= prompt_quiesce:
                p = self._prompt_tail(last["output"], loose=False)
                if p:
                    return self._as_awaiting(last, p)

            if time.time() >= idle_deadline:
                # Full idle: a prompt-shaped tail ⇒ interactive (don't strand the model); otherwise
                # it's a real long-running command — report it running so the model polls.
                p = self._prompt_tail(last["output"], loose=True)
                if p:
                    return self._as_awaiting(last, p)
                last["timed_out"] = "idle"
                return last

        last["timed_out"] = "hard"
        p = self._prompt_tail(last["output"], loose=True)
        if p:
            return self._as_awaiting(last, p)
        return last

    def _as_awaiting(self, result: dict, prompt: str) -> dict:
        """Mark a result as 'sitting at an interactive prompt'. Clears the (dead) command marker so
        a later read()/check_terminal returns a coherent not-running state instead of spinning on a
        marker the REPL will never emit."""
        self.marker = None
        result["running"] = False
        result["awaiting_input"] = True
        result["prompt"] = prompt
        return result

    # ── interactive driving (no marker — read by output quiescence) ──────────
    def send_raw(self, keys: str):
        """Type raw bytes into the session with NO completion marker, for driving a REPL/child.
        Clears the buffer first so the next quiescent read returns only this turn's output."""
        self.buf = ""
        self.last_cmd = ""
        self.marker = None
        self.cmd_start = time.time()
        self._last_output_len = 0
        self._raw_send(keys)

    def read_quiescent(self, idle: float = 1.2, max_wait: float = 45, poll: float = 0.4) -> str:
        """Read until the output stream has been quiet for `idle` seconds (the program stopped
        writing and is presumably waiting), or `max_wait` elapses. Returns the cleaned screen — how
        a human reads an interactive program, independent of any shell dialect or marker."""
        deadline = time.time() + max_wait
        last_change = time.time()
        prev_len = len(self.buf)
        while time.time() < deadline:
            self._drain(poll)
            if len(self.buf) > prev_len:
                prev_len = len(self.buf)
                last_change = time.time()
            if time.time() - last_change >= idle:
                break
        return self._strip_runtime_warnings(self._clean(self.buf)).strip("\n")

    def interrupt(self) -> str:
        """Send Ctrl-C to the running command. Returns current terminal output so caller
        can verify whether the shell is clean or still inside a REPL."""
        self._raw_send("\x03")
        time.sleep(0.5)
        self._drain(0.5)
        output = self._clean(self.buf)
        # Clear marker so subsequent read() calls return running=False instead of
        # spinning forever waiting for a marker that the killed command never printed.
        self.marker = None
        self.buf = ""
        self.mode = "bash"   # Ctrl-C is an escape toward the shell; assume we're heading back
        return output

    def send_keys(self, keys: str):
        """Send raw keystrokes (for interactive prompts: 'y\\n', 'yes\\n', etc.)."""
        self._raw_send(keys)
        time.sleep(0.2)
        self._drain(0.2)

    # ── recovery from an undriveable interactive child ───────────
    def _reassert_prompt(self):
        """Re-establish the quiet, echo-off bash prompt this terminal expects. Harmless if we're
        currently inside a REPL (the lines are just ignored/errored there); takes effect once we're
        back at bash."""
        self._raw_send("export PS1='' ; stty -echo 2>/dev/null ; unalias -a 2>/dev/null\n")
        time.sleep(0.2)
        self._drain(0.2)

    def _probe_clean(self) -> bool:
        """Round-trip a marked echo. Succeeds ONLY if the top-level bash executes it (the marker
        comes back) — which is exactly the definition of 'the shell is driveable again'. If we're
        stuck in a child REPL, the marker line is consumed by the child and never returns, so this
        fails. That makes the escalation in reset_to_clean_prompt safe-by-construction: a failed
        probe PROVES we are not at a responsive top shell, so the subsequent exit/quit sequences
        target the child REPL, never the session's own bash."""
        self.send("echo __SHELL_OK__")
        res = self.wait(max_wait=6, idle_wait=4)
        return (not res["running"]) and res.get("exit_code") == 0

    def reset_to_clean_prompt(self, max_attempts: int = 4) -> bool:
        """Force this terminal back to a known-clean bash prompt, whatever interactive child it is
        stuck in (meterpreter, smb:\\>, mysql>, python>>>, a hung command, …). Deterministic and
        bounded — the harness owns shell state rather than asking a blind model to type its own way
        out. Returns True if a clean bash was confirmed.

        Strategy: try the gentle path first (Ctrl-C + re-probe — covers a command that errored but
        stayed in bash). Only if the probe fails — proving we're inside a child REPL, see
        _probe_clean — do we send REPL-exit sequences, which then cannot harm the top shell."""
        # Attempt 0 — gentle: cancel the current line, re-probe.
        self._raw_send("\x03")
        time.sleep(0.3)
        self._drain(0.3)
        self._reassert_prompt()
        if self._probe_clean():
            self.marker = None
            self.buf = ""
            self.mode = "bash"
            return True

        # Probe failed ⇒ we are inside a child REPL. Escalate with exits that target the child.
        for seq in ("exit\r\n", "quit\r\n", "\x04", "exit -y\r\n"):
            self._raw_send("\x03")
            time.sleep(0.2)
            self._raw_send(seq)
            time.sleep(0.3)
            self._drain(0.3)
            self._reassert_prompt()
            if self._probe_clean():
                self.marker = None
                self.buf = ""
                self.mode = "bash"
                return True
        return False

    def close(self):
        try:
            self.chan.close()
        except Exception:
            pass
