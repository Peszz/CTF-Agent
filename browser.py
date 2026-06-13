"""
Playwright browser controller for the Kali CTF agent.

Uploads a small controller script to Kali and runs it as a persistent process
over a dedicated SSH exec channel. The agent sends JSON commands on stdin and
reads JSON responses from stdout — so the browser lives on Kali (on the target
network / VPN) for the entire engagement.

Requires on Kali:
    pip install playwright
    playwright install chromium
"""

import json
import textwrap
import builtins


def _log(msg: str):
    """Route through agent output sink if active, otherwise stdout."""
    try:
        import agent as _agent
        if _agent._OUT is not None:
            _agent._OUT(msg)
            return
    except Exception:
        pass
    builtins.print(msg)


# ── Controller script that runs on Kali ──────────────────────────────────────
# Embedded here so there is no separate file to distribute.
_CONTROLLER = textwrap.dedent("""\
    import sys, json, base64

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    except ImportError:
        print(json.dumps({"error": "playwright not installed — run: pip install playwright && playwright install chromium"}), flush=True)
        sys.exit(1)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            ignore_https_errors=True,
        )
        page = ctx.new_page()

        sys.stdout.write(json.dumps({"ready": True}) + "\\n")
        sys.stdout.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                cmd = json.loads(line)
            except Exception:
                sys.stdout.write(json.dumps({"ok": False, "error": "invalid json"}) + "\\n")
                sys.stdout.flush()
                continue

            action = cmd.get("action", "")
            try:
                if action == "navigate":
                    resp = page.goto(cmd["url"], timeout=300000, wait_until="domcontentloaded")
                    result = {
                        "ok": True,
                        "url": page.url,
                        "title": page.title(),
                        "status": resp.status if resp else None,
                    }

                elif action == "content":
                    try:
                        body_text = page.inner_text("body")
                    except Exception:
                        body_text = ""
                    result = {
                        "ok": True,
                        "url": page.url,
                        "title": page.title(),
                        "text": body_text[:8000],
                        "source": page.content()[:8000],
                    }

                elif action == "click":
                    page.click(cmd["selector"], timeout=10000)
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except PlaywrightTimeoutError:
                        pass
                    result = {"ok": True, "url": page.url}

                elif action == "fill":
                    # Explicit short timeout so a bad selector fails in ~8s, not
                    # Playwright's silent 30s default (which burned whole runs).
                    page.fill(cmd["selector"], cmd["value"], timeout=cmd.get("timeout", 8000))
                    result = {"ok": True, "url": page.url}

                elif action == "press":
                    page.press(cmd["selector"], cmd["key"], timeout=cmd.get("timeout", 8000))
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except PlaywrightTimeoutError:
                        pass
                    result = {"ok": True, "url": page.url}

                elif action == "evaluate":
                    val = page.evaluate(cmd["script"])
                    result = {"ok": True, "result": str(val)[:4000]}

                elif action == "screenshot":
                    img = page.screenshot(full_page=cmd.get("full_page", False))
                    path = "/tmp/ctf_screenshot.png"
                    with open(path, "wb") as fh:
                        fh.write(img)
                    result = {
                        "ok": True,
                        "path": path,
                        "png_b64": base64.b64encode(img).decode(),
                    }

                elif action == "cookies":
                    result = {"ok": True, "cookies": ctx.cookies()}

                elif action == "set_cookies":
                    ctx.add_cookies(cmd["cookies"])
                    result = {"ok": True}

                elif action == "quit":
                    sys.stdout.write(json.dumps({"ok": True}) + "\\n")
                    sys.stdout.flush()
                    break

                else:
                    result = {"ok": False, "error": f"unknown action: {action}"}

            except PlaywrightTimeoutError as e:
                try:
                    current_url   = page.url
                    current_title = page.title()
                except Exception:
                    current_url   = None
                    current_title = None

                sel = cmd.get("selector")
                if sel is not None:
                    # Selector-based action (fill/click/press) timed out. This is
                    # almost never a redirect — the selector didn't match or the
                    # element wasn't actionable. Tell the caller WHY and list the
                    # form controls that actually exist, so it can pick a real
                    # selector instead of guessing the same wrong one again.
                    try:
                        matched = page.locator(sel).count()
                    except Exception:
                        matched = -1
                    try:
                        fields = page.evaluate("() => Array.from(document.querySelectorAll('input,textarea,select,button')).slice(0,40).map(el => ({tag: el.tagName.toLowerCase(), type: el.getAttribute('type'), name: el.getAttribute('name'), id: el.id || null, placeholder: el.getAttribute('placeholder'), label: (el.value || el.innerText || '').trim().slice(0,40), visible: el.offsetParent !== null}))")
                    except Exception:
                        fields = []
                    if matched == 0:
                        reason = "selector matched 0 elements on the page"
                    elif matched > 0:
                        reason = f"selector matched {matched} element(s) but none became visible/editable in time"
                    else:
                        reason = "selector is invalid CSS/Playwright syntax"
                    result = {
                        "ok":               False,
                        "error":            "selector_failed",
                        "action":           action,
                        "selector":         sel,
                        "matched_elements": matched,
                        "reason":           reason,
                        "available_fields": fields,
                        "url":              current_url,
                        "hint": (
                            "Pick a selector from available_fields — e.g. "
                            "input[name='theusername'] or #id (name/id/placeholder/label "
                            "are shown for each control). If available_fields is empty the "
                            "form is likely inside an <iframe>; query the frame, or just "
                            "POST the login with curl instead of driving the browser."
                        ),
                    }
                else:
                    # Navigation-style timeout: the page may have followed a redirect —
                    # page.url shows where it actually ended up.
                    result = {
                        "ok":          False,
                        "error":       "timeout",
                        "current_url": current_url,
                        "title":       current_title,
                        "hint": (
                            f"Page timed out but browser is at: {current_url}. "
                            "If this differs from the URL you requested, the server "
                            "redirected — navigate directly to current_url."
                            if current_url and current_url != cmd.get("url")
                            else "Page timed out with no redirect detected."
                        ),
                    }
            except Exception as e:
                result = {"ok": False, "error": str(e)}

            sys.stdout.write(json.dumps(result) + "\\n")
            sys.stdout.flush()

        browser.close()
""")

_SCRIPT_PATH = "/tmp/_ctf_browser_ctrl.py"


def _ssh_run(client, cmd: str) -> tuple[int, str]:
    _, stdout, stderr = client.exec_command(cmd, get_pty=False)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    return stdout.channel.recv_exit_status(), out + err


class BrowserController:
    def __init__(self, ssh_client):
        self.client = ssh_client
        self._stdin = None
        self._stdout = None
        self._ready = False

    # ── lifecycle ─────────────────────────────────────────────────

    def _ensure_playwright(self):
        """Install Playwright + Chromium if not already present."""
        # Check playwright import
        code, _ = _ssh_run(self.client, "python3 -c 'import playwright'")
        if code != 0:
            _log("  [browser] installing Playwright on Kali (first-time)...")
            code, out = _ssh_run(self.client, "pip install playwright")
            if code != 0:
                raise RuntimeError(f"pip install playwright failed:\n{out}")

        # Check chromium is actually installed (not just the Python package)
        code, _ = _ssh_run(self.client, "python3 -c 'from playwright.sync_api import sync_playwright; p=sync_playwright().start(); p.chromium.executable_path; p.stop()'")
        if code != 0:
            _log("  [browser] installing Chromium for Playwright...")
            # Use python3 -m playwright, NOT the system `playwright` CLI —
            # the apt-installed Node.js playwright breaks on Node.js v24+.
            code, out = _ssh_run(self.client, "python3 -m playwright install chromium --with-deps")
            if code != 0:
                raise RuntimeError(f"playwright install chromium failed:\n{out}")
        _log("  [browser] Playwright + Chromium ready.")

    def _upload(self):
        sftp = self.client.open_sftp()
        with sftp.open(_SCRIPT_PATH, "w") as f:
            f.write(_CONTROLLER)
        sftp.close()

    def _start(self):
        self._ensure_playwright()
        self._upload()
        self._stdin, self._stdout, self._stderr = self.client.exec_command(
            f"python3 {_SCRIPT_PATH}", get_pty=False
        )
        # Wait up to 30s for the ready signal — guards against silent startup crashes.
        self._stdout.channel.settimeout(30)
        try:
            line = self._stdout.readline()
        except Exception:
            err = self._stderr.read().decode("utf-8", "replace")
            raise RuntimeError(f"Browser controller timed out on startup.\nstderr: {err or '(empty)'}")
        finally:
            self._stdout.channel.settimeout(None)

        if not line.strip():
            # Process exited without printing anything — grab stderr for the real reason
            err = self._stderr.read().decode("utf-8", "replace")
            raise RuntimeError(
                f"Browser controller exited silently on startup.\n"
                f"stderr: {err.strip() or '(empty)'}\n"
                f"Fix: run on Kali: python3 -m playwright install chromium --with-deps"
            )
        try:
            msg = json.loads(line.strip())
        except Exception:
            raise RuntimeError(f"Browser controller sent non-JSON on startup: {line!r}")
        if "error" in msg:
            raise RuntimeError(msg["error"])
        self._ready = True

    def _ensure(self):
        if not self._ready or self._stdin.channel.closed:
            self._start()

    def _send(self, cmd: dict) -> dict:
        self._ensure()
        self._stdin.write(json.dumps(cmd) + "\n")
        self._stdin.flush()
        self._stdout.channel.settimeout(330)
        try:
            line = self._stdout.readline()
        except Exception:
            self._ready = False
            return {"ok": False, "error": "browser controller timed out waiting for response"}
        finally:
            self._stdout.channel.settimeout(None)
        if not line:
            self._ready = False
            return {"ok": False, "error": "browser controller closed unexpectedly"}
        try:
            return json.loads(line.strip())
        except Exception as e:
            return {"ok": False, "error": f"bad response: {e} | raw: {line!r}"}

    def close(self):
        if self._ready:
            try:
                self._send({"action": "quit"})
            except Exception:
                pass
            self._ready = False

    # ── actions ───────────────────────────────────────────────────

    def navigate(self, url: str) -> dict:
        return self._send({"action": "navigate", "url": url})

    def get_content(self) -> dict:
        return self._send({"action": "content"})

    def click(self, selector: str) -> dict:
        return self._send({"action": "click", "selector": selector})

    def fill(self, selector: str, value: str) -> dict:
        return self._send({"action": "fill", "selector": selector, "value": value})

    def press(self, selector: str, key: str) -> dict:
        return self._send({"action": "press", "selector": selector, "key": key})

    def evaluate(self, script: str) -> dict:
        return self._send({"action": "evaluate", "script": script})

    def screenshot(self, full_page: bool = False) -> dict:
        return self._send({"action": "screenshot", "full_page": full_page})

    def get_cookies(self) -> dict:
        return self._send({"action": "cookies"})

    def set_cookies(self, cookies: list) -> dict:
        return self._send({"action": "set_cookies", "cookies": cookies})
