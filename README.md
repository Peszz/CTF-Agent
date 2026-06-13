# Kali CTF Agent Harness

A harness that connects a local LLM (via LM Studio) to a Kali Linux VM over SSH,
giving the model real persistent terminals, a browser, and reverse-shell handling
so it can run a CTF / pentest engagement autonomously — recon → research → exploit
→ flag — with no hints required.

---

## Architecture

```
  You / your prompt  (live nudges via the TUI)
        │
        ▼
  ┌─────────────────┐        HTTP (OpenAI-compatible API)   ┌───────────────────┐
  │  agent.py       │ ◄───────────────────────────────────► │   LM Studio       │
  │  (harness)      │                                        │  (localhost:1234) │
  └─────────────────┘                                        └───────────────────┘
        │
        │  SSH (paramiko) — MULTIPLE persistent terminal sessions
        │  default backend: tmux on Kali (reads the rendered screen via capture-pane)
        ▼
  ┌────────────────────────────────────────────┐
  │   Kali Linux VM                            │ ── NAT/host adapter ──► internet
  │   • main shell + extra sessions            │      (web_search / web_fetch / github)
  │   • netcat listeners (catch reverse shells)│
  │   • Playwright browser (renders JS)        │ ── HTB/lab VPN (tun0) ─► target box
  └────────────────────────────────────────────┘
```

The harness holds **real persistent terminals** on Kali. State carries across
commands (cd, env vars, running jobs), the model can start a slow scan, poll it,
and Ctrl-C it, run multiple sessions at once (e.g. hold a pivot in one while
scanning from another), catch reverse shells on a listener and run commands *on
the target* through them — exactly like a human at a terminal.

It also keeps **persistent memory** across the run (and across runs): a notes file,
a working plan of ranked hypotheses, and a lessons/CVE store. These survive context
compaction so the model doesn't lose what it has already learned.

## The model's tools

**Terminal & sessions**

| Tool | Purpose |
|------|---------|
| `run_command` | Run a command in a persistent session; waits up to `wait`s (idle-timeout, hard cap 600s), returns output + exit code, or `running=true` if still going. `session=` targets another shell or a caught reverse shell |
| `check_terminal` | Poll a long-running command; returns output-so-far + running flag |
| `interrupt_terminal` | Send Ctrl-C to a stuck/pointless command |
| `send_keys` | Drive interactive programs (msfconsole, meterpreter, mysql>, ftp>, python>>>, y/n & password prompts) and read the live screen back |
| `new_session` / `list_sessions` / `close_session` | Open/list/close additional persistent shells (pivots, captures, port-forwards) |
| `read_file` | Read a file on Kali via SFTP |

**Reverse shells**

| Tool | Purpose |
|------|---------|
| `start_listener` | Start a netcat listener to catch a reverse shell; returns your attack IP, port, and session name |
| `shell_status` | Check whether a reverse shell has connected back yet (safe to poll) |

**Recon & research**

| Tool | Purpose |
|------|---------|
| `web_search` | Search the web (DuckDuckGo) for versions/CVEs/advisories |
| `web_fetch` | Fetch a page's readable text; full page is saved to disk on Kali for re-reading |
| `github_search` | Search public GitHub for exploits / PoCs / tools |
| `github_fetch_file` | Read a raw file from a public GitHub repo |

**Memory**

| Tool | Purpose |
|------|---------|
| `note_finding` / `read_notes` | Record / review evidence-grounded findings (services, creds, endpoints, dead ends) |
| `update_plan` | Maintain ≥2 ranked hypotheses, each with evidence + the experiment that would confirm/kill it |
| `lookup_lessons` / `save_lesson` | Pull / store CVE facts and re-runnable exploit playbooks from past engagements |

**Browser (Playwright on Kali)**

| Tool | Purpose |
|------|---------|
| `browser_navigate` | Primary tool for any HTTP/HTTPS target — renders JS, follows redirects, keeps sessions |
| `browser_get_content` | Read the current page's visible text + HTML source |
| `browser_click` / `browser_fill` / `browser_press` | Interact with pages and forms by CSS selector |
| `browser_evaluate` | Run JS (read localStorage, cookies, DOM state) |
| `browser_get_cookies` | Dump session cookies/tokens |
| `browser_screenshot` | Screenshot the page to `/tmp/ctf_screenshot.png` |

**Control flow**

| Tool | Purpose |
|------|---------|
| `submit_flag` | Submit a flag (`which='user'` continues for privesc; `which='root'` ends the run) |
| `declare_stuck` | Give up after exhausting approaches (ends the run) |
| `load_writeup` / `advance_step` | Load a walkthrough and be driven through it one pinned step at a time |

The intended autonomous loop: recon → identify exact software + version →
`web_search` / `github_search` → `web_fetch` the advisory/exploit → exploit (msf /
searchsploit / manual / reverse shell) → flag.

---

## 1. Prerequisites

### On your host machine
- Python 3.10+
- LM Studio installed and running
- A model loaded that supports **tool/function calling** (see below)

### Recommended models
The default is a small reasoning model; reasoning models "think" before acting and
fail far less on tricky interactive states. Set the exact ID in `config.py` (or
override per-run with `--model`).

| Model | VRAM | Notes |
|-------|------|-------|
| **google/gemma-4-12b-qat** (default) | ~7–8 GB | Gemma 4 QAT — native tool calling + thinking, small/fast |
| qwen3-32b | ~20 GB | Strong reasoning, best balance |
| qwq-32b | ~20 GB | Reasoning specialist, great at multi-step plans |
| qwen3-30b-a3b | ~18 GB | MoE, fast, nearly as good as 32B dense |
| qwen2.5-72b-instruct | ~45 GB | Best non-reasoning option if you have the VRAM |
| llama-3.3-70b-instruct | ~45 GB | Good general reasoning |

> ⚠️ Models **without** tool calling (base models, many older llamas) will not work.
> For reasoning models, enable **thinking** in LM Studio and keep `max_tokens >= 4096`.
> Sampling (temperature / top_p / top_k) is selected **automatically** from the model
> id — Qwen → 0.6/0.95/20, Gemma → 1.0/0.95/64, otherwise a balanced default — so you
> only ever change `model`. See `_SAMPLING_PROFILES` in `config.py`.

### On the Kali VM
- SSH server running: `sudo systemctl enable ssh && sudo systemctl start ssh`
- `tmux` installed (the default terminal backend; ships with Kali)
- Playwright/Chromium for the browser tools — installed automatically on first
  browser use, or manually: `pip install playwright && playwright install chromium`
  (set `browser_enabled = False` in `config.py` to disable)
- Note your VM's IP: `ip addr show eth0` or `hostname -I`

---

## 2. Install

On the host:

```bash
pip install -r requirements.txt
```

(`paramiko`, `requests`, `prompt_toolkit`. Playwright runs on Kali, not the host.)

---

## 3. Configure

All settings live in the `Config` class in `config.py`. Edit the fields:

```python
class Config:
    lm_studio_url = "http://localhost:1234"      # LM Studio default
    model         = "google/gemma-4-12b-qat"     # exact ID from LM Studio's API tab
    terminal_backend = "tmux"                    # or "invoke_shell"

    kali_host     = "192.168.80.128"             # your Kali VM IP
    kali_port     = 22
    kali_user     = "kali"
    kali_password = "kali"                        # set to None to use key auth
    kali_key_file = None                          # e.g. "~/.ssh/kali_ctf"

    browser_enabled = True
    github_token    = None                        # optional, raises GitHub rate limits
```

Anything here can be overridden per-run on the command line (see Usage) without
editing the file.

### SSH key auth (optional, more secure)
```bash
# On host:
ssh-keygen -t ed25519 -f ~/.ssh/kali_ctf
ssh-copy-id -i ~/.ssh/kali_ctf.pub kali@192.168.80.128

# In config.py:
kali_password = None
kali_key_file = "~/.ssh/kali_ctf"
```

### LM Studio setup
1. Open LM Studio and load your chosen model
2. Go to the **Developer / Local Server** tab and **Start Server**
3. Copy the model identifier shown there → paste into `config.py` (or pass `--model`)

---

## 4. Usage

`agent.py` takes the target IP as a positional argument and **requires**
`-td/--target-domain` (the full hostname, used for `/etc/hosts` and run-directory
naming). `--tui` is recommended — it gives a split-screen view and lets you type
nudges mid-run.

```bash
# Basic run, plain terminal output
python agent.py 10.10.11.42 --target-domain example.htb

# With split-screen TUI (recommended)
python agent.py 10.10.11.42 --target-domain example.htb --tui

# Override the model for this run
python agent.py 10.10.11.42 -td example.htb --tui --model qwen3-32b

# Different Kali box
python agent.py 10.10.11.42 -td example.htb --tui --kali-host 192.168.1.50 --kali-password kali

# Separate log file per target so runs don't overwrite each other
python agent.py 10.10.11.42 -td example.htb --tui --log logs/example.json
```

Overrides available: `--model`, `--kali-host`, `--kali-port`, `--kali-user`,
`--kali-password`, `--lm-url`, `--log`. Run `python agent.py -h` for the full list.

**In the TUI:** type to send a nudge mid-run, **ESC** to pause, **Ctrl-Q** to quit.

The engagement runs until the model submits a root flag, declares itself stuck, or
a safety limit trips (step ceiling, wall-clock ceiling, or a loop/stall detector
after the model ignores a nudge — all tunable in `config.py`).

### Interactive / chat mode (you guide it step by step)
```bash
python chat.py
```
Chat mode reuses the same tools and tool dispatcher as the autonomous agent, so it
always stays in sync.

---

## 5. VM network setup tips

### VirtualBox
- For lab/CTF targets, give Kali a NIC that can reach the target (HTB uses a VPN, so
  a plain **NAT** adapter for internet + the VPN inside Kali is the common setup)
- Use **Host-only Adapter** only if both host and Kali are isolated together

### VMware
- **NAT** for internet, run the lab VPN (e.g. HTB `.ovpn`) inside Kali

### WSL2
- Kali is reachable at the WSL IP shown in `ip addr` (usually `172.x.x.x`)

The host needs SSH reachability to Kali; Kali needs reachability to the target
(typically over `tun0`).

---

## 6. Logs & artifacts

- `session_log.json` — autonomous runs (override with `--log`)
- `chat_session_log.json` — interactive runs
- Fetched pages, screenshots, and write-ups are saved on the Kali VM (under the run
  directory / `/tmp`) so the model can re-read them after they scroll out of context

Logs contain every command, output, and LLM message — useful for reviewing exactly
what the model did.

---

## 7. Troubleshooting

**"Connection refused" on SSH**
→ Start SSH on Kali: `sudo systemctl start ssh`, and check `kali_host`/`kali_port`.

**LLM not calling tools / just talks**
→ Your model may not support tool calling, or thinking/`max_tokens` is too low. Use
one of the recommended models with thinking enabled.

**Commands time out**
→ Raise the per-call `wait` (the model can pass a higher value), or the limits in
`config.py`.

**LM Studio returns 404**
→ Make sure the server is started and the `model` id matches LM Studio's API tab exactly.

**Browser tools error**
→ Playwright/Chromium not installed on Kali, or `browser_enabled = False`. Install
with `pip install playwright && playwright install chromium` on the VM.

**`tmux: command not found` / weird terminal behaviour**
→ Install `tmux` on Kali, or set `terminal_backend = "invoke_shell"` in `config.py`.

**Output too long / context overflow**
→ Lower `max_output_chars` in `config.py` or raise the model's context window in LM Studio.
