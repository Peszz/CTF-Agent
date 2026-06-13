"""
Configuration for the NSEC CTF Agent Harness.
Edit the values below to match your setup.
"""

# ── Per-model sampling profiles ─────────────────────────────────────
# Each model wants different sampling; the harness drives BOTH Qwen and Gemma (or anything else)
# off the single `model` setting. The active profile is matched by a case-insensitive substring
# of the model id, and Config exposes temperature/top_p/top_k as properties that resolve through
# here on every read — so a `--model` override at launch (which reassigns cfg.model AFTER Config()
# is built) still picks up the right sampling. Values verified against each model's card.
_SAMPLING_PROFILES = {
    # Gemma 4 (LM Studio card + Google docs): temp 1.0, top_p 0.95, top_k 64, repeat_penalty 1.0.
    "gemma": {"temperature": 1.0, "top_p": 0.95, "top_k": 64},
    # Qwen3.x thinking-mode (model card): temp 0.6, top_p 0.95, top_k 20. Very low temp feeds
    # repetition/looping on a default-thinking model — don't drop below ~0.6.
    "qwen":  {"temperature": 0.6, "top_p": 0.95, "top_k": 20},
}
# Fallback for an unmatched model id (e.g. llama-3.3, or a future model): a balanced middle.
_DEFAULT_SAMPLING = {"temperature": 0.7, "top_p": 0.95, "top_k": 40}


def sampling_for(model: str) -> dict:
    """Return {'name', 'temperature', 'top_p', 'top_k'} for a model id (substring match)."""
    ml = (model or "").lower()
    for key, prof in _SAMPLING_PROFILES.items():
        if key in ml:
            return {"name": key, **prof}
    return {"name": "default", **_DEFAULT_SAMPLING}


class Config:
    # ── LM Studio ──────────────────────────────────────────────────
    # LM Studio default: runs on localhost:1234
    lm_studio_url: str = "http://localhost:1234"

    # The model identifier shown in LM Studio (copy it from the UI)
    # NOTE: Your model MUST support function/tool calling.
    #
    # Recommended models for CTF/pentest work (ranked):
    #
    #  BEST — reasoning models (think before acting, far fewer REPL/loop failures):
    #   - gemma-4-12b-qat    QAT ~7-8GB — Gemma 4, native tool calling + thinking, small/fast
    #   - qwen3-32b          Q4 ~20GB — strong reasoning, tool calling, best balance
    #   - qwq-32b            Q4 ~20GB — reasoning specialist, excellent at multi-step plans
    #   - qwen3-30b-a3b      Q4 ~18GB — MoE, fast, nearly as good as 32B dense
    #
    #  GOOD — instruction models (solid but no explicit thinking step):
    #   - qwen2.5-72b-instruct   Q4 ~45GB — best non-reasoning option if you have the VRAM
    #   - qwen2.5-32b-instruct   Q4 ~20GB — current model, decent but loops on tricky states
    #   - llama-3.3-70b-instruct Q4 ~45GB — good general reasoning
    #
    #  For reasoning models, enable thinking in LM Studio and set max_tokens >= 4096.
    #
    #  Switching models: change `model` only — sampling auto-follows via the profile table above
    #  (Qwen -> temp 0.6/top_k 20; Gemma -> temp 1.0/top_k 64). Both are default-thinking models,
    #  so keep thinking ENABLED in LM Studio. Both do native tool calling.
    model: str = "google/gemma-4-12b-qat"  # exact ID shown in LM Studio's API tab

    max_tokens: int = 8192        # Reasoning models need headroom for their thinking step

    # Sampling resolves from the model id on every read (see _SAMPLING_PROFILES) so a --model
    # override still gets the right values. To force a model into a different profile, edit the
    # table above rather than these properties.
    @property
    def sampling(self) -> dict:
        return sampling_for(self.model)

    @property
    def sampling_profile(self) -> str:
        return self.sampling["name"]

    @property
    def temperature(self) -> float:
        return self.sampling["temperature"]

    @property
    def top_p(self) -> float:
        return self.sampling["top_p"]

    @property
    def top_k(self) -> int:
        return self.sampling["top_k"]

    # ── Terminal backend ────────────────────────────────────────────
    # "invoke_shell" (default) — paramiko invoke_shell channel per session, marker + quiescence
    #                            driver in terminal.py. Proven path.
    # "tmux"         — run tmux on Kali; read the RENDERED screen via capture-pane (tmux does the
    #                  terminal emulation), drive REPLs by send-keys + quiescence. Matches how
    #                  Strix/tmux-agents handle interactive sessions. Requires `tmux` on Kali
    #                  (installed by default on Kali). Live-validated 2026-06-12 (11/11 backend +
    #                  6/6 end-to-end: marker/exit-codes, quoting/heredoc paste, output isolation,
    #                  python REPL detect+drive, REPL→bash, listener nc detection). Revert to
    #                  "invoke_shell" if a full engagement surfaces a timing/edge issue.
    terminal_backend: str = "tmux"

    # ── Kali VM SSH ─────────────────────────────────────────────────
    kali_host: str = "192.168.80.128"   # Your Kali VM IP
    kali_port: int = 22
    kali_user: str = "kali"
    
    # Use ONE of the following auth methods:
    kali_password: str = "kali"         # Set to None if using key auth
    kali_key_file: str = None           # Path to your SSH key, e.g. "~/.ssh/id_rsa"

    # ── Agent Behaviour ─────────────────────────────────────────────
    # The engagement runs until the model wins (submit_flag).
    # Only gives up (declare_stuck), or the loop detector forces a stop after the model ignores a nudge.
    loop_threshold: int = 5            # Same failing approach N times = a loop
    stale_window: int = 15             # N actions with nothing new tried = circling
    empty_research_threshold: int = 4  # N web/github searches returning nothing = a research spin
    tool_fail_threshold: int = 4       # N consecutive errors on one channel (e.g. browser) = dead channel
    stall_seconds: int = 600           # No new finding for this long → nudge; 2x → force stop (progress-stall)
    max_steps: int = 150               # Hard step ceiling (far backstop; progress-stall stops stuck runs sooner)
    max_wall_seconds: int = 4500       # Hard wall-clock ceiling (75 min) — a "step" varies 2-60s, so bound time too
    max_output_chars: int = 8000       # Truncate command output beyond this

    # ── Browser (Playwright on Kali) ────────────────────────────────
    # Set False if Playwright isn't installed on Kali yet.
    # Browser calls will return an error + curl fallback hint instead of crashing.
    browser_enabled: bool = True

    # ── GitHub ──────────────────────────────────────────────────────
    # Optional personal access token for higher search rate limits (30/min vs 10/min).
    # No scopes needed — public repo access only.
    github_token: str = None

    # ── Logging ─────────────────────────────────────────────────────
    log_file: str = "session_log.json"
