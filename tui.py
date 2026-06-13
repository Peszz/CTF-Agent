"""
Split-screen terminal UI for the CTF agent (prompt_toolkit).

Layout (top to bottom):
  ┌──────────────────────────────────────────┐
  │  scrollable output area (agent activity)   │   <- FormattedTextControl
  ├──────────────────────────────────────────┤
  │  status bar                                │   <- one line
  ├──────────────────────────────────────────┤
  │ > your nudge here_                          │   <- pinned input, always typeable
  └──────────────────────────────────────────┘

Keys:
  enter       submit nudge to the agent
  page-up/dn  scroll output
  up/down     scroll output one line
  end         jump back to bottom (resume live follow)
  esc         request agent stop current action
  ctrl-q      quit
"""

import re
import threading
import queue

from prompt_toolkit import Application
from prompt_toolkit.layout import Layout, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl, BufferControl
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.layout.processors import BeforeInput
from prompt_toolkit.mouse_events import MouseEventType, MouseEvent

_PAGE = 20   # lines per page-up/page-down

# ── text sanitising ──────────────────────────────────────────────────────────
# prompt_toolkit renders a full-screen buffer and diffs it against the terminal. Any control
# character that moves the cursor or miscounts a cell width (backspace, bell, vertical-tab,
# form-feed, a *partial* escape sequence, a literal tab PT measures differently than the terminal)
# desyncs that diff and leaves ghost characters bleeding between rows — the intermittent "looks
# weird" corruption. So scrub control bytes at every ingest point. SGR colour escapes (ESC[…m) are
# kept because the output pane renders them via ANSI(); everything else in C0/DEL is dropped, and
# tabs are expanded to spaces (PT does not expand them to tab stops the way a terminal does).
#
# Range note: \x0e-\x1a then \x1c-\x1f deliberately straddles ESC (\x1b) so colour escapes survive;
# \x09 (tab) and \x0a (newline) are handled separately, not stripped here.
_OUTPUT_CTRL_RE = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")
# Status is a single reverse-video row: no colour needed, and a newline there is the surest desync,
# so strip ALL control bytes including ESC and flatten whitespace to one line.
_STATUS_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_STATUS_MAX = 240   # hard cap so a runaway status string can never matter


def _sanitize_output(text: str) -> str:
    """Scrub a line bound for the scrolling output pane. Keeps SGR colour escapes, drops every
    other control byte, expands tabs. (Newlines are split by the caller before this runs.)"""
    text = str(text).replace("\x00", "").replace("\r", "").expandtabs(4)
    text = _OUTPUT_CTRL_RE.sub("", text)
    # drop a bare/partial ESC (one not starting a real CSI "[…" sequence) — a lone ESC desyncs too
    return re.sub(r"\x1b(?!\[)", "", text)


def _sanitize_status(text: str) -> str:
    """Scrub a status string bound for the one-row status bar: no control bytes at all, single line."""
    text = _STATUS_CTRL_RE.sub(" ", str(text))
    return re.sub(r"\s+", " ", text).strip()[:_STATUS_MAX]


class _ScrollableTextControl(FormattedTextControl):
    """FormattedTextControl with mouse-wheel scrolling via overridden mouse_handler."""
    def __init__(self, *args, on_scroll_up=None, on_scroll_down=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_scroll_up = on_scroll_up
        self._on_scroll_down = on_scroll_down

    def mouse_handler(self, mouse_event: MouseEvent):
        if mouse_event.event_type == MouseEventType.SCROLL_UP and self._on_scroll_up:
            self._on_scroll_up()
        elif mouse_event.event_type == MouseEventType.SCROLL_DOWN and self._on_scroll_down:
            self._on_scroll_down()
        else:
            return super().mouse_handler(mouse_event)


class AgentTUI:
    def __init__(self, title="CTF AGENT"):
        self.title = title
        self._lines = []
        self._max_lines = 5000
        self._scroll_offset = 0      # lines from bottom; 0 = live/follow mode
        self._window_height = 40     # updated each render from render_info
        self.nudge_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.quit_event = threading.Event()
        self._status = "starting..."
        self._lock = threading.Lock()
        self.on_quit = None   # callable — set by caller for graceful shutdown
        self.worker = None    # Thread reference — set in run(), readable after TUI exits

        # ── output window ───────────────────────────────────────
        self.output_control = _ScrollableTextControl(
            text=self._render_output,
            focusable=False,
            on_scroll_up=self._scroll_up,
            on_scroll_down=self._scroll_down,
        )
        self._output_window = Window(
            content=self.output_control,
            wrap_lines=True,
            always_hide_cursor=True,
        )

        # ── status bar ──────────────────────────────────────────
        self.status_control = FormattedTextControl(text=self._render_status)
        status_window = Window(content=self.status_control, height=1, style="reverse")

        # ── input line ──────────────────────────────────────────
        self.input_buffer = Buffer(accept_handler=self._on_accept, multiline=False)
        input_window = Window(
            content=BufferControl(
                buffer=self.input_buffer,
                input_processors=[BeforeInput("> ")],
            ),
            height=1,
        )

        root = HSplit([
            self._output_window,
            status_window,
            input_window,
        ])

        self.app = Application(
            layout=Layout(root, focused_element=input_window),
            key_bindings=self._keybindings(),
            full_screen=True,
            mouse_support=True,
        )

    # ── mouse ───────────────────────────────────────────────────

    def _scroll_up(self):
        with self._lock:
            total = len(self._lines)
        max_scroll = max(0, total - self._window_height)
        self._scroll_offset = min(self._scroll_offset + 3, max_scroll)
        self._invalidate()

    def _scroll_down(self):
        self._scroll_offset = max(0, self._scroll_offset - 3)
        self._invalidate()

    # ── rendering ───────────────────────────────────────────────

    def _render_output(self):
        with self._lock:
            lines = list(self._lines)

        # Keep window_height in sync so scroll clamping stays accurate
        ri = getattr(self._output_window, 'render_info', None)
        if ri is not None and getattr(ri, 'window_height', None):
            self._window_height = max(1, ri.window_height)

        total = len(lines)
        h = self._window_height

        if self._scroll_offset == 0:
            # Live mode: always show the most recent h lines
            visible = lines[max(0, total - h):]
        else:
            end = max(0, total - self._scroll_offset)
            start = max(0, end - h)
            visible = lines[start:end]

        return ANSI("\n".join(visible))

    def _render_status(self):
        if self._scroll_offset > 0:
            scroll_hint = f"\x1b[93m  ↑ scrolled {self._scroll_offset} lines — End to follow \x1b[0m"
        else:
            scroll_hint = "\x1b[2m  PgUp/PgDn scroll \x1b[0m"
        return ANSI(f" {self._status}   {scroll_hint}  \x1b[2m esc stop · ctrl-q quit \x1b[0m")

    # ── input handling ──────────────────────────────────────────

    def _on_accept(self, buff):
        text = buff.text.strip()
        if text:
            self.nudge_queue.put(text)
            self.write(f"\x1b[96m[you] {text}\x1b[0m")
        return False

    def _keybindings(self):
        kb = KeyBindings()

        @kb.add("c-q")
        def _(event):
            if self.on_quit:
                self.on_quit()  # redirect output + signal agent to stop gracefully
            self.quit_event.set()
            event.app.exit()

        @kb.add("escape", eager=True)
        def _(event):
            self.stop_event.set()
            self.write("\x1b[93m[esc] stop requested — agent will halt current action\x1b[0m")

        @kb.add("pageup")
        def _(event):
            for _ in range(_PAGE):
                self._scroll_up()

        @kb.add("pagedown")
        def _(event):
            for _ in range(_PAGE):
                self._scroll_down()

        @kb.add("up")
        def _(event):
            self._scroll_up()

        @kb.add("down")
        def _(event):
            self._scroll_down()

        @kb.add("end")
        def _(event):
            self._scroll_offset = 0
            self._invalidate()

        return kb

    # ── public API (called from agent thread) ───────────────────

    def _invalidate(self):
        try:
            self.app.invalidate()
        except Exception:
            pass

    def write(self, text: str):
        text = str(text).replace("\x00", "").replace("\r", "")
        with self._lock:
            for line in text.split("\n"):
                self._lines.append(_sanitize_output(line))
            if len(self._lines) > self._max_lines:
                self._lines = self._lines[-self._max_lines:]
        # only auto-scroll to bottom if user hasn't scrolled up
        if self._scroll_offset == 0:
            self._invalidate()

    def set_status(self, status: str):
        self._status = _sanitize_status(status)
        self._invalidate()

    def consume_nudges(self) -> list:
        out = []
        while True:
            try:
                out.append(self.nudge_queue.get_nowait())
            except queue.Empty:
                break
        return out

    def run(self, agent_main):
        self.worker = threading.Thread(target=self._safe_worker, args=(agent_main,), daemon=True)
        self.worker.start()
        self.app.run()
        # Returns when the TUI exits (Ctrl-Q or natural finish).
        # Caller is responsible for joining self.worker if graceful shutdown is needed.

    def _safe_worker(self, agent_main):
        try:
            agent_main(self)
        except Exception as e:
            import traceback
            self.write(f"\x1b[91m[agent crashed] {e}\x1b[0m")
            self.write("\x1b[90m" + traceback.format_exc() + "\x1b[0m")
            self.set_status("crashed — ctrl-q to quit")
        else:
            self.set_status("done — ctrl-q to quit")
