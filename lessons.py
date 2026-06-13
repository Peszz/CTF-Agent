"""
Lessons store: re-runnable exploit playbooks + CVE facts.

Two kinds of cross-run memory, both CONCRETE. Generalised strategy is deliberately
NOT stored here — it lives in the system prompt so it can't drift or self-contradict
across runs (the old generalised-lesson files were the "pendulum" contradiction engine
and have been removed root-and-branch).

  lessons/playbooks/<product>.md  — the winning exploit chain for a product (software +
                                    version), captured from the run trajectory at run end.
  lessons/cve/CVE-XXXX-NNNNN.md   — facts about a specific CVE (affected versions,
                                    PoC/tool that worked, gotchas).

During a run the model calls lookup_lessons(topic) to pull only the relevant file on
demand — nothing is bulk-injected at startup.

Inspired by the closed-learning-loop pattern in
https://github.com/nousresearch/hermes-agent
"""

import json
import re
import hashlib
import datetime
from pathlib import Path

LESSONS_DIR = Path(__file__).parent / "lessons"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# Strip <think>...</think> reasoning from qwen3 / other reasoning-model output.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


# ─── re-runnable exploit playbooks ───────────────────────────────────────────
# A playbook is the concrete WINNING chain for one product (software + version),
# stored verbatim so a future run against the same software can replay it — the
# opposite of the generalised one-line lessons above. Keyed by product slug and
# fed from the actual command/tool trajectory, not the model's self-curated notes.

PLAYBOOKS_SUBDIR = "playbooks"
# Backstop cap. The caller (_build_trajectory_transcript) already anchors on the winning
# chain and budgets to ~16k keeping the structured facts, so this should rarely bite. When
# it does, keep BOTH ends (head = recon/fingerprint → product+version; tail = the exploit
# that won) — never a pure tail-cut, which is what dropped the real chain in run 3.
_MAX_TRANSCRIPT_CHARS = 18_000

_PLAYBOOK_PROMPT = (
    "You just SOLVED (or partially solved) a CTF/pentest target. Distill ONLY the winning path "
    "into a concrete, RE-RUNNABLE playbook a future agent can replay against the same software — "
    "not a generalised tip. Keep every reproducible specific: exact endpoints, parameters, "
    "payloads, commands, CVE IDs, and the software name + version. Drop all dead ends and failed "
    "attempts — keep only the steps that actually worked, in order, from first access to the flag.\n\n"
    "Rules:\n"
    "  - Replace the target's IP and hostname with the literal placeholder <target> — the IP is "
    "ephemeral and changes on reboot. Keep everything else verbatim.\n"
    "  - Every step must be runnable: give the actual command or HTTP request/payload, not a "
    "description of it.\n"
    "  - For browser steps, give the URL plus the selector/field/JS payload that worked.\n\n"
    "Return ONLY a JSON object (no prose, no markdown fences):\n"
    "{\n"
    '  "software": "<product name, e.g. FreePBX>",\n'
    '  "version":  "<version if known, else empty string>",\n'
    '  "cves":     ["CVE-XXXX-NNNNN", ...],\n'
    '  "steps": [\n'
    '    {"goal": "<what this step achieves>",\n'
    '     "action": "<exact command / HTTP request / browser action + payload>",\n'
    '     "result": "<what it returns / why it works>"}\n'
    "  ],\n"
    '  "flag_path": "<where and how the flag was obtained>"\n'
    "}\n"
    "Return {} only if no exploitation actually happened."
)


# ─── public helpers ──────────────────────────────────────────────────────────

def is_cve(s: str) -> bool:
    """True if `s` is a well-formed CVE id. The store accepts CVE facts only, so callers
    use this to gate save_lesson before persisting."""
    return bool(_CVE_RE.match((s or "").strip()))


# ─── internal helpers ────────────────────────────────────────────────────────

def _cve_file(cve_id: str) -> Path:
    return LESSONS_DIR / "cve" / f"{cve_id.upper()}.md"


def _append_cve(cve_id: str, lesson: dict, target: str, date: str, outcome: str) -> bool:
    """Write or update a CVE entry. Each CVE file holds one structured record.
    Returns True if anything was written/updated, False if fully duplicate."""
    filepath = _cve_file(cve_id)
    filepath.parent.mkdir(parents=True, exist_ok=True)

    entry_line = f"- [{date} | {target} | {outcome}] {lesson['lesson']}"

    if filepath.exists():
        content = filepath.read_text(encoding="utf-8")
        if lesson["lesson"] in content:
            return False
        content = content.rstrip() + "\n" + entry_line + "\n"
    else:
        content = (
            f"# {cve_id.upper()}\n\n"
            f"## Software\n{lesson.get('software', 'unknown')}\n\n"
            f"## Notes\n{entry_line}\n"
        )

    filepath.write_text(content, encoding="utf-8", newline="\n")
    return True


def _rel(path: Path) -> str:
    return str(path.relative_to(LESSONS_DIR)).replace("\\", "/")


def _slug(text: str) -> str:
    """Filesystem-safe product slug, e.g. 'FreePBX 16' → 'freepbx-16'."""
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "unknown"


def _indent(text: str, prefix: str = "     ") -> str:
    return "\n".join(prefix + ln for ln in text.splitlines())


# ─── public API (called from agent.py) ───────────────────────────────────────

def list_available() -> str:
    """Return a short listing of the playbooks and CVE facts on file."""
    if not LESSONS_DIR.exists():
        return "No lessons collected yet."
    files = [f for f in sorted(LESSONS_DIR.rglob("*.md")) if f.stat().st_size > 0]
    if not files:
        return "No lessons collected yet."
    cve_files      = [f for f in files if f.parent.name == "cve"]
    playbook_files = [f for f in files if f.parent.name == PLAYBOOKS_SUBDIR]
    lines = ["Available lessons (pass one to lookup_lessons):"]
    if playbook_files:
        lines.append(
            "  Re-runnable exploit playbooks (full chains — look these up by product name "
            f"the moment you fingerprint the software): {', '.join(f.stem for f in playbook_files)}"
        )
    if cve_files:
        lines.append(f"  CVEs on file: {', '.join(f.stem for f in cve_files)}")
    return "\n".join(lines)


def lookup(topic: str) -> str:
    """Return lesson content for the given topic keyword or relative path.

    topic='list'             → list available topics
    topic='CVE-2025-57819'   → that CVE's file
    topic='cve' / 'playbooks'→ ALL files under that directory
    topic='freepbx'          → playbook/CVE files whose path matches the product name
    Falls back to substring match across all files.
    """
    if topic.strip().lower() == "list":
        return list_available()

    # CVE direct lookup: "CVE-2025-57819" → lessons/cve/CVE-2025-57819.md
    if _CVE_RE.match(topic.strip()):
        filepath = _cve_file(topic.strip())
        if filepath.exists() and filepath.stat().st_size > 0:
            return filepath.read_text(encoding="utf-8").strip()
        return f"No lesson on file for {topic.strip().upper()} yet."

    key = topic.strip().lower().removesuffix(".md")

    # Directory-level lookup: "web" → all files in lessons/web/
    # "privesc" → all files in lessons/privesc/, etc.
    subdir = LESSONS_DIR / key
    if subdir.exists() and subdir.is_dir():
        files = sorted(subdir.rglob("*.md"))
        parts = [f.read_text(encoding="utf-8").strip() for f in files if f.stat().st_size > 0]
        if parts:
            return "\n\n".join(parts)
        return f"No lessons yet under '{topic}/'. " + list_available()

    # Direct relative path (e.g. "playbooks/freepbx", "cve/CVE-2025-57819")
    for candidate in (LESSONS_DIR / key, LESSONS_DIR / (key + ".md")):
        if candidate.exists() and candidate.stat().st_size > 0:
            return candidate.read_text(encoding="utf-8").strip()

    # Substring match across all file paths
    matches = [
        f for f in sorted(LESSONS_DIR.rglob("*.md"))
        if key in _rel(f) and f.stat().st_size > 0
    ]
    if matches:
        return "\n\n".join(f.read_text(encoding="utf-8").strip() for f in matches)

    return f"No lessons found for '{topic}'. " + list_available()


def save_one(lesson: str, category: str, tags: list, target: str,
             outcome: str = "in_progress", cve: str = "") -> bool:
    """Persist a single CONFIRMED FACT mid-run (save_lesson tool) — CVE-ONLY.
    Routes to lessons/cve/CVE-XXXX-NNNNN.md. The store holds CVE facts + concrete playbooks
    ONLY; there is deliberately NO path to write generalised/strategy files. The old
    tag→web/privesc/general.md routing WAS the "pendulum" contradiction engine (auto-accreted
    platitudes that contradicted each other and the system prompt across runs), so a save
    without a valid CVE is now rejected rather than written. Version/config facts are already
    captured into the run's playbook; operating doctrine lives in the system prompt.
    Returns True only if a valid CVE fact was written (False = no valid CVE, or duplicate)."""
    cve = (cve or "").strip()
    if not _CVE_RE.match(cve):
        return False
    LESSONS_DIR.mkdir(exist_ok=True)
    date = datetime.datetime.now().isoformat()[:10]
    entry = {"category": category, "lesson": lesson, "tags": tags}
    return _append_cve(cve, entry, target, date, outcome)


# ─── re-runnable playbook capture (called from agent.py at run end) ───────────

def build_playbook_messages(transcript: str, outcome: str) -> list:
    """Build the two-message payload for post-run exploit-playbook extraction.
    `transcript` is the actual action+output trajectory, not the model's notes."""
    if len(transcript) > _MAX_TRANSCRIPT_CHARS:
        # Head+tail, not pure tail: keep the recon/fingerprint (product+version lives here)
        # AND the exploit at the end. Dropping the head is what made run 3 hallucinate the version.
        head = int(_MAX_TRANSCRIPT_CHARS * 0.4)
        tail = _MAX_TRANSCRIPT_CHARS - head
        transcript = transcript[:head] + "\n[...middle of run elided...]\n" + transcript[-tail:]
    return [
        {
            "role": "system",
            "content": "You are a CTF/pentest analyst. Extract re-runnable exploit "
                       "playbooks from solved engagements.",
        },
        {
            "role": "user",
            "content": (
                "/no_think\nENGAGEMENT TRANSCRIPT (actions and outputs, oldest first):\n"
                f"{transcript}\n\nOutcome: {outcome}\n\n{_PLAYBOOK_PROMPT}"
            ),
        },
    ]


def parse_playbook(text: str) -> dict:
    """Strip reasoning tags / fences and parse the playbook JSON object.
    Falls back to the first {...} block if the model wrapped it in prose."""
    text = _THINK_RE.sub("", text).strip()
    text = re.sub(r"```(?:json)?\n?|\n?```", "", text).strip()
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {}
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return {}
        try:
            obj = json.loads(m.group(0))
            return obj if isinstance(obj, dict) else {}
        except json.JSONDecodeError:
            return {}


def save_playbook(pb: dict, target: str, outcome: str) -> str:
    """Persist a structured, re-runnable exploit chain to lessons/playbooks/<software>.md,
    keyed by product so a future run can replay it. Cross-references any CVEs into the CVE
    store. Returns the relative path written, or "" if nothing saved (empty/duplicate)."""
    steps = [
        s for s in (pb.get("steps") or [])
        if isinstance(s, dict) and (s.get("action") or "").strip()
    ]
    software = (pb.get("software") or "").strip()
    if not steps or not software:
        return ""

    filepath = LESSONS_DIR / PLAYBOOKS_SUBDIR / f"{_slug(software)}.md"
    filepath.parent.mkdir(parents=True, exist_ok=True)

    version = (pb.get("version") or "").strip()
    cves    = [c.strip() for c in (pb.get("cves") or []) if isinstance(c, str) and c.strip()]
    date    = datetime.datetime.now().isoformat()[:10]

    # Stable signature so the same chain isn't written twice across reruns.
    sig = hashlib.sha1(
        ("|".join([software, version] + [s.get("action", "") for s in steps])).encode("utf-8")
    ).hexdigest()[:12]

    if filepath.exists():
        existing = filepath.read_text(encoding="utf-8")
        if f"sig:{sig}" in existing:
            return ""
    else:
        existing = f"# {software} — Exploit Playbooks\n"

    out = [f"\n## {date} | {software} {version}".rstrip() + f"  <!-- sig:{sig} -->"]
    if cves:
        out.append(f"CVEs: {', '.join(cves)}")
    out.append(f"Outcome: {outcome}")
    out.append("")
    for i, s in enumerate(steps, 1):
        out.append(f"{i}. {(s.get('goal') or '').strip()}".rstrip())
        out.append(_indent((s.get("action") or "").strip()))
        res = (s.get("result") or "").strip()
        if res:
            out.append(f"   -> {res}")
    flag_path = (pb.get("flag_path") or "").strip()
    if flag_path:
        out.append(f"\nFlag: {flag_path}")

    filepath.write_text(
        existing.rstrip() + "\n" + "\n".join(out) + "\n",
        encoding="utf-8", newline="\n",
    )

    rel = _rel(filepath)
    for cve in cves:
        if _CVE_RE.match(cve):
            _append_cve(
                cve,
                {"lesson": f"Full re-runnable chain: {rel}",
                 "software": f"{software} {version}".strip()},
                target, date, outcome,
            )
    return rel
