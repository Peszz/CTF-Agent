"""
tmux-backed terminal session (alternative to terminal.py's invoke_shell driver).

WHY: the invoke_shell driver reads a RAW byte stream and reconstructs terminal state by hand
(stripping ANSI, echo, reconstructing the screen) — and the bash completion-marker only works in
bash, so any child REPL went blind until the quiescence driver was added. The established autonomous
pentest agents (Strix uses libtmux; the broad tmux-agent ecosystem) avoid all of that by letting
tmux BE the terminal emulator and reading the *rendered* screen with `capture-pane`. That sidesteps
ANSI/echo entirely and makes "read what's on screen, type the next thing" — the human model — the
native operation.

This module runs ONE tmux server on Kali (over the existing SSH connection, driven by one-shot
`exec_command` control calls — NOT invoke_shell). Each harness session is a tmux session:
  - run a command  → paste it into the pane + Enter, poll `capture-pane` until a completion marker
                     appears (bash) or the screen settles at a prompt (REPL / waiting for input).
  - interactive    → `send_keys`/paste input, read the rendered screen back each turn (never blind).
  - multi-session  → another tmux session (no extra SSH channels).
  - reverse shell  → `nc` is the pane's foreground process; the caught shell drops when
                     `pane_current_command` is no longer `nc` (cleaner than channel-EOF detection).

`TmuxTerminal` mirrors the public surface KaliSSH calls on `terminal.Terminal` (send / wait / read /
send_raw / read_quiescent / send_keys / interrupt / reset_to_clean_prompt / _probe_clean /
_prompt_tail / mode / close) so it is a drop-in, selected by `Config.terminal_backend == "tmux"`.
"""

import re
import time
import uuid
import shlex

from terminal import Terminal, _SCAN_NOISE_RE  # reuse prompt-shape detection + the shared scan-noise filter

# A recognisable bash prompt so "we're back at the Kali shell" is unambiguous in the rendered pane.
# Ends in a sigil so the generic prompt detector also sees it; the literal tag makes it identifiable.
_BASH_PS1 = "CTFSH$ "
_BASH_PROMPT_RE = re.compile(r"CTFSH\$\s*$", re.MULTILINE)

# ── completion-marker shapes (for cleaning) ──────────────────────────────────
# Cleaning strips markers by their fixed SHAPE (random 10-hex wrapped in fixed sigils), not by the
# currently-active token. A marker can land AFTER its token was cleared — e.g. the folded END
# marker prints only once a driven REPL exits, by which point _as_awaiting has nulled self.marker —
# so token-keyed stripping would miss it. The shapes are specific enough never to hit real output.
_MARK_END_OUT  = re.compile(r"RC[0-9a-f]{10}EOC\d*")                      # executed END marker
_MARK_END_ECHO = re.compile(r"\s*;?\s*printf '%s%s' 'RC[0-9a-f]{10}' 'EOC'\$\?.*$")  # echoed END printf (folded or standalone)
_MARK_ST_ECHO  = re.compile(r"printf '%s%s[^\n]*'ST'")                    # echoed START printf
_MARK_ST_OUT   = re.compile(r"^ST[0-9a-f]{10}$")                         # executed START marker (whole line)


class TmuxTerminal:
    def __init__(self, ssh_client, name: str = "main", width: int = 220, height: int = 50,
                 exec_timeout: int = 15):
        self.client = ssh_client
        self.name = name
        self.ts = "ctf_" + re.sub(r"[^A-Za-z0-9_]", "_", name)[:28]   # tmux session name
        self.width = width
        self.height = height
        self.exec_timeout = exec_timeout
        self.mode = "bash"                  # "bash" (marker) | "interactive" (quiescence) — as terminal.py
        self.marker = None                  # active completion marker token, or None
        self.last_cmd = ""
        self.cmd_start = time.time()
        self._last_capture = ""
        self._start_server()

    # ── low-level tmux control (one-shot SSH exec) ───────────────
    def _ssh(self, cmd: str) -> str:
        """Run a shell command on Kali over a one-shot exec channel; return stdout (stderr ignored)."""
        try:
            _in, out, _err = self.client.exec_command(cmd, timeout=self.exec_timeout)
            return out.read().decode("utf-8", "replace")
        except Exception:
            return ""

    def _start_server(self):
        # Create a detached tmux session with a clean, identifiable prompt. Idempotent: a second
        # new-session for an existing name fails harmlessly (2>/dev/null).
        self._ssh(
            f"tmux new-session -d -s {self.ts} -x {self.width} -y {self.height} 2>/dev/null; "
            f"tmux set-option -t {self.ts} -g history-limit 5000 2>/dev/null; true"
        )
        # Quiet, identifiable shell prompt; disable bracketed-paste so pastes execute cleanly.
        self._paste(f"export PS1={shlex.quote(_BASH_PS1)}; bind 'set enable-bracketed-paste off' 2>/dev/null; clear\n")
        time.sleep(0.3)
        self._ssh(f"tmux clear-history -t {self.ts} 2>/dev/null; true")

    def _paste(self, text: str):
        """Type `text` into the pane literally (handles spaces, quotes, and newlines/heredocs) by
        staging it through a PER-SESSION tmux buffer — the robust equivalent of typing it at the
        keyboard. The named buffer (-b) keeps concurrent sessions from clobbering each other."""
        q = shlex.quote(text)
        self._ssh(f"printf %s {q} | tmux load-buffer -b {self.ts} - 2>/dev/null && "
                  f"tmux paste-buffer -b {self.ts} -t {self.ts} -d 2>/dev/null; true")

    def capture(self, full: bool = True) -> str:
        """The rendered pane, already free of ANSI/cursor noise — tmux does the terminal emulation.
        -J rejoins wrapped lines. full=True grabs scrollback (for marker extraction); full=False just
        the visible screen (for interactive turns, so output stays bounded to what's on screen)."""
        scroll = "-S -2000" if full else ""
        raw = self._ssh(f"tmux capture-pane -p -J {scroll} -t {self.ts} 2>/dev/null")
        return raw.rstrip("\n")

    def _pane_command(self) -> str:
        """The foreground process in the pane (e.g. 'bash', 'nc', 'mysql'). Used for listener-death."""
        return self._ssh(f"tmux display-message -p -t {self.ts} '#{{pane_current_command}}' 2>/dev/null").strip()

    # ── completion-marker helpers (pure, unit-tested) ────────────
    # capture-pane returns the WHOLE scrollback every poll, so a single end-marker isn't enough —
    # we'd hand the model the entire session each turn. Bracket the command with a START and an END
    # marker (pwncat's approach) and return only what's BETWEEN them = just this command's output.
    @staticmethod
    def _arm() -> str:
        return uuid.uuid4().hex[:10]

    @staticmethod
    def _start_line(tok: str) -> str:
        # printf-split so the ECHOED line ('printf .. ST .. tok') can't match the EXECUTED 'STtok'.
        return f"printf '%s%s\\n' 'ST' '{tok}'"

    @staticmethod
    def _marker_line(tok: str) -> str:
        return f"printf '%s%s' 'RC{tok}' 'EOC'$?"

    @staticmethod
    def _extract(text: str, tok: str):
        """Return (done, exit_code, output) using the START/END markers. Output is the slice between
        the executed start marker and the executed end marker — i.e. only THIS command's output,
        independent of scrollback. If start hasn't appeared yet, fall back to the whole text."""
        sm = re.search(r"ST" + re.escape(tok) + r"\n", text)
        body_start = sm.end() if sm else 0
        em = re.search(r"RC" + re.escape(tok) + r"EOC(\d+)", text[body_start:])
        if em:
            return True, int(em.group(1)), text[body_start: body_start + em.start()]
        return False, None, text[body_start:]

    @staticmethod
    def _clean_output(text: str, tok: str = "") -> str:
        """Drop harness bookkeeping (marker echoes, executed markers, the bash sentinel prompt) so the
        model sees the command's actual output. Markers are stripped by their fixed SHAPE (see the
        _MARK_* regexes) rather than the active token, so a marker that lands after its token was
        cleared — the folded END marker printing once a driven REPL exits — is still removed. Keeps
        the typed command and any REPL prompt: a folded echo ('nmap ... ; printf ...RC..EOC$?') has
        only the printf tail stripped, leaving 'nmap ...' visible — the same thing a human sees."""
        # drop nmap/NSE packet-trace spam (SENT/RCVD/...) — same filter the invoke_shell backend uses
        text = _SCAN_NOISE_RE.sub("", text)
        out = []
        for ln in text.split("\n"):
            s = re.sub(r"^CTFSH\$\s?", "", ln.rstrip())   # strip leading sentinel prompt prefix
            if _MARK_ST_ECHO.search(s) or _MARK_ST_OUT.match(s.strip()):
                continue                                  # START bookkeeping — whole line is ours
            s = _MARK_END_ECHO.sub("", s)                 # echoed END printf (folded tail or standalone)
            s = _MARK_END_OUT.sub("", s)                  # executed END marker token (may be glued to a prompt)
            if _BASH_PROMPT_RE.search(s):                 # a trailing sentinel prompt
                s = _BASH_PROMPT_RE.sub("", s).rstrip()
            out.append(s)
        return "\n".join(out).strip("\n")

    # ── public API (drop-in for terminal.Terminal) ──────────────
    def send(self, command: str):
        """Arm a completion marker and run `command` in the pane (bash mode)."""
        tok = self._arm()
        self.marker = tok
        self.last_cmd = command
        self.cmd_start = time.time()
        self._last_capture = ""
        start, end = self._start_line(tok), self._marker_line(tok)
        # FOLD the END marker onto the command's line for single-line foreground commands, so it is
        # NOT left sitting as typeahead in the tty input buffer. Tools that read stdin WHILE running
        # — nmap (runtime keypress interaction), and any REPL — would otherwise CONSUME the queued
        # marker line: the END printf never executes, the command looks stuck forever (exit_code
        # -999), and a REPL gets the marker text typed INTO it. On one line bash parses command+marker
        # before the command runs, so the tty buffer is empty and the marker fires once the command
        # returns. Multiline/heredoc and backgrounded commands keep the marker on its own line: a
        # heredoc body is read by the heredoc (not typeahead), and a '&' command returns to the prompt
        # at once so nothing is left running to eat the marker.
        stripped = command.rstrip()
        single_line = "\n" not in stripped
        backgrounded = stripped.endswith("&") and not stripped.endswith("&&")
        if single_line and not backgrounded:
            body = stripped.rstrip(";").rstrip()
            self._paste(f"{start}\n{body} ; {end}\n")
        else:
            self._paste(f"{start}\n{command}\n{end}\n")

    def _snapshot(self) -> dict:
        """One poll: capture the pane and classify (done via markers / waiting at prompt / running).
        Output is isolated to the current command via the START/END markers (not the whole pane)."""
        text = self.capture()
        elapsed = round(time.time() - self.cmd_start, 1)
        if self.marker:
            found, rc, body = self._extract(text, self.marker)
            out = self._clean_output(body, self.marker)
            if found:
                return {"output": out, "running": False, "exit_code": rc,
                        "elapsed_seconds": elapsed, "_raw": text}
            return {"output": out, "running": True, "exit_code": None,
                    "elapsed_seconds": elapsed, "_raw": text}
        out = self._clean_output(text)
        return {"output": out, "running": True, "exit_code": None,
                "elapsed_seconds": elapsed, "_raw": text}

    def read(self, wait: float = 0.6) -> dict:
        time.sleep(min(wait, 1.0))
        snap = self._snapshot()
        snap.pop("_raw", None)
        if self.marker is None:
            snap["running"] = False
        return snap

    def wait(self, max_wait=600, idle_wait=30, poll=0.6, prompt_quiesce=1.2) -> dict:
        """Block until the marker appears (done), the screen settles at a prompt (awaiting_input), or
        a timeout fires. Mirrors terminal.Terminal.wait so KaliSSH treats both backends identically."""
        hard = time.time() + max_wait
        idle_deadline = time.time() + idle_wait
        last_change = time.time()
        prev = ""
        last = {"output": "", "running": True, "exit_code": None, "elapsed_seconds": 0.0}
        while time.time() < hard:
            time.sleep(poll)
            snap = self._snapshot()
            raw = snap.pop("_raw", "")
            last = snap
            if not snap["running"]:
                return snap  # marker found → completed in bash
            if raw != prev:
                prev = raw
                idle_deadline = time.time() + idle_wait
                last_change = time.time()
            quiet_for = time.time() - last_change
            if quiet_for >= prompt_quiesce:
                p = Terminal._prompt_tail(snap["output"], loose=False)
                if p and not _BASH_PROMPT_RE.search(snap["output"][-80:]):
                    return self._as_awaiting(snap, p)
            if time.time() >= idle_deadline:
                p = Terminal._prompt_tail(snap["output"], loose=True)
                if p and not _BASH_PROMPT_RE.search(snap["output"][-80:]):
                    return self._as_awaiting(snap, p)
                last["timed_out"] = "idle"
                return last
        last["timed_out"] = "hard"
        return last

    def _as_awaiting(self, result: dict, prompt: str) -> dict:
        self.marker = None
        result["running"] = False
        result["awaiting_input"] = True
        result["prompt"] = prompt
        return result

    # ── interactive driving (no marker — read the rendered screen) ──
    def send_raw(self, keys: str):
        self.marker = None
        self.last_cmd = ""
        self.cmd_start = time.time()
        self._last_capture = self.capture()
        self._paste(keys)

    def read_quiescent(self, idle: float = 1.2, max_wait: float = 45, poll: float = 0.5) -> str:
        """Read the rendered screen until it stops changing for `idle`s (the program went quiet /
        is waiting). Quiescence is screen-diff based — exactly how a human notices it stopped."""
        deadline = time.time() + max_wait
        prev = self.capture(full=False)
        last_change = time.time()
        while time.time() < deadline:
            time.sleep(poll)
            cur = self.capture(full=False)
            if cur != prev:
                prev = cur
                last_change = time.time()
            elif time.time() - last_change >= idle:
                break
        return self._clean_output(prev)

    def send_keys(self, keys: str):
        """Send raw keystrokes (prompt answers / control). Newline → Enter; otherwise literal."""
        self._paste(keys)
        time.sleep(0.2)

    def interrupt(self) -> str:
        self._ssh(f"tmux send-keys -t {self.ts} C-c 2>/dev/null; true")
        time.sleep(0.4)
        self.marker = None
        self.mode = "bash"
        return self.capture()

    # ── recovery (drop-in for terminal.Terminal) ────────────────
    def _probe_clean(self) -> bool:
        tok = self._arm()
        self._paste(self._marker_line(tok) + "\n")
        deadline = time.time() + 6
        while time.time() < deadline:
            time.sleep(0.4)
            found, rc, _ = self._extract(self.capture(), tok)
            if found:
                return True
        return False

    def reset_to_clean_prompt(self, max_attempts: int = 4) -> bool:
        self._ssh(f"tmux send-keys -t {self.ts} C-c 2>/dev/null; true")
        time.sleep(0.3)
        if self._probe_clean():
            self.marker = None
            self.mode = "bash"
            return True
        for seq in ("exit", "quit", "exit -y"):
            self._ssh(f"tmux send-keys -t {self.ts} C-c 2>/dev/null; true")
            time.sleep(0.2)
            self._paste(seq + "\n")
            time.sleep(0.3)
            if self._probe_clean():
                self.marker = None
                self.mode = "bash"
                return True
        return False

    @staticmethod
    def _prompt_tail(text: str, loose: bool = False) -> str:
        return Terminal._prompt_tail(text, loose=loose)

    # ── listener support ────────────────────────────────────────
    def start_nc_listener(self, port: int):
        """Run nc as the pane's foreground process so the pane reflects the caught shell's life."""
        self.send_keys(f"exec nc -lvnp {port}\n")
        time.sleep(0.5)

    def listener_dead(self) -> bool:
        """True once nc is no longer the pane's foreground process (reverse shell dropped / not yet
        running). Cleaner than channel-EOF: tmux tells us exactly what the pane is running."""
        cmd = self._pane_command().lower()
        return cmd not in ("nc", "nc.traditional", "ncat", "netcat")

    def close(self):
        try:
            self._ssh(f"tmux kill-session -t {self.ts} 2>/dev/null; true")
        except Exception:
            pass

    # back-compat shim: KaliSSH._chan_dead pokes `.chan`; tmux has no channel object.
    chan = None
