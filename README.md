# Kali CTF Agent Harness

A harness that connects a local LLM (via LM Studio) to a Kali Linux VM over SSH,
giving the model a full terminal so it can run any Kali tool autonomously.

---

## Architecture

```
  You / your prompt
        │
        ▼
  ┌─────────────────┐        HTTP (OpenAI API)      ┌──────────────────┐
  │  agent.py       │ ◄──────────────────────────► │   LM Studio      │
  │  (harness)      │                               │  (localhost:1234) │
  └─────────────────┘                               └──────────────────┘
        │
        │  SSH — ONE persistent interactive terminal (paramiko invoke_shell)
        ▼
  ┌──────────────────┐
  │   Kali Linux VM  │ ── NAT adapter ──► internet (web_search / web_fetch)
  │  (full terminal) │ ── HTB VPN (tun0) ─► target box
  └──────────────────┘
```

The harness holds a **real persistent terminal** on Kali. State carries across
commands (cd, env vars, running jobs), and the model can start a slow scan, see
it's still running, poll it, and Ctrl-C it — exactly like a human at a terminal.

## The model's tools

| Tool | Purpose |
|------|---------|
| `run_command` | Run a command; waits up to `wait`s, returns full output or `running=true` if still going |
| `check_terminal` | Poll a long-running command; returns output-so-far + running flag |
| `interrupt_terminal` | Send Ctrl-C to a stuck/pointless command |
| `send_keys` | Type into interactive tools (msfconsole, y/n prompts, ssh sessions) |
| `read_file` | Read a file on Kali via SFTP |
| `web_search` | Search the web (DuckDuckGo) to research versions/CVEs it discovers |
| `web_fetch` | Read a full advisory / exploit write-up page |

The intended autonomous loop: recon → identify exact software + version →
`web_search` the version → `web_fetch` the advisory → find the exploit (msf /
searchsploit / manual) → exploit → flag. No hints required.

---

## 1. Prerequisites

### On your host machine
- Python 3.10+
- LM Studio installed and running
- A model loaded that supports **tool/function calling**

### Recommended models (tool-calling support confirmed)
| Model | VRAM | Quality |
|-------|------|---------|
| Qwen2.5-72B-Instruct-Q4 | ~40GB | Excellent |
| Llama-3.1-70B-Instruct-Q4 | ~40GB | Excellent |
| Qwen2.5-14B-Instruct-Q5 | ~10GB | Very good |
| Qwen2.5-7B-Instruct-Q5 | ~5GB | Good |
| Mistral-Nemo-Instruct-2407 | ~8GB | Good |

> ⚠️ Models WITHOUT tool calling (e.g. base models, many older llamas) will not work.
> In LM Studio, look for models tagged "Instruct" and check if tool calling is listed.

### On Kali VM
- SSH server running: `sudo systemctl enable ssh && sudo systemctl start ssh`
- Note your VM's IP: `ip addr`

---

## 2. Install

```bash
pip install -r requirements.txt
```

---

## 3. Configure

Edit `config.py`:

```python
lm_studio_url = "http://localhost:1234"   # LM Studio default
model = "your-model-name-here"            # Copy from LM Studio UI
kali_host = "192.168.56.101"              # Your Kali VM IP
kali_user = "kali"
kali_password = "kali"                    # Or use kali_key_file
```

### Finding your Kali IP
In Kali: `ip addr show eth0` or `hostname -I`

### SSH key auth (optional, more secure)
```bash
# On host:
ssh-keygen -t ed25519 -f ~/.ssh/kali_ctf
ssh-copy-id -i ~/.ssh/kali_ctf.pub kali@192.168.56.101

# In config.py:
kali_password = None
kali_key_file = "~/.ssh/kali_ctf"
```

### LM Studio Setup
1. Open LM Studio
2. Load your chosen model
3. Go to **Local Server** tab
4. Click **Start Server**
5. Make sure "Enable CORS" is on
6. Copy the model identifier shown in the server tab → paste into `config.py`

---

## 4. Usage

### Autonomous mode (agent runs until it finds the flag)
```bash
python3 agent.py 10.10.10.5
python3 agent.py http://ctf-box.local
```

### Interactive / chat mode (you guide it step by step)
```bash
python3 chat.py
```

Chat mode example session:
```
You > there's a web app on port 80, start with recon
Agent > Running nmap and then checking the web headers...
  [KALI] $ nmap -sV -p 80 10.10.10.5
  ...
You > try gobuster on that
Agent > Sure, running directory enumeration...
```

---

## 5. VM Network Setup Tips

### VirtualBox
- Set Kali NIC to **Host-only Adapter** (vboxnet0)
- Host and Kali can talk, but Kali is isolated from internet (good for CTF boxes)
- Or use **NAT Network** if Kali also needs internet access

### VMware
- Use **Host-only** or **Custom VMnet** for isolation

### WSL2
- Kali is accessible at the WSL IP shown in `ip addr`
- Usually `172.x.x.x`

---

## 6. Session Logs

Every run saves a full JSON log:
- `session_log.json` — autonomous runs
- `chat_session_log.json` — interactive runs

Contains every command, output, and LLM message. Great for reviewing what the model did.

---

## 7. Troubleshooting

**"Connection refused" on SSH**
→ Make sure SSH is running on Kali: `sudo systemctl start ssh`

**LLM not calling tools / just talks**
→ Your model may not support tool calling. Try Qwen2.5-7B-Instruct or Llama-3.1-8B-Instruct.

**Commands time out**
→ Increase `timeout` in config, or the model can pass a higher timeout per-call.

**LM Studio returns 404**
→ Make sure the server is started in LM Studio and the model name in config.py matches exactly.

**Output too long / context overflow**
→ Lower `max_output_chars` in config.py or increase your model's context window in LM Studio.
