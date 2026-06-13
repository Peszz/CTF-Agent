"""
Lead tracking — turning OBSERVATIONS into OBLIGATIONS.

The recurring failure this fixes: the model enumerates correctly — finds the right SMB,
sees a readable share, watches a Groups.xml / id_rsa / web.config scroll past in the
listing — and then MOVES ON. It treats having SEEN the loot as having DONE something.
Observation is not progress; extraction is. A readable file you have not read is not a
finding, it is an OPEN LEAD.

The prompt already says "read the loot, don't just confirm access and move on" — and the
model ignores it. Prose is spent. This module makes the harness enforce it structurally,
in the same spirit as loopdetect: the model can't quietly walk past the win.

Two classes of high-value lead are watched, both keyed for PRECISION (a false lead would
wrongly block a legitimate give-up, so generic names like config/backup/passwords are
deliberately excluded):

  1. KNOWN-LOOT FILENAMES — files whose mere appearance in a listing is the win
     (GPP cpassword XML, SSH private keys, KeePass DBs, framework secret configs).
  2. CONFIRMED-READABLE SMB SHARES — an `smbclient -c 'ls'` that returns a directory
     listing instead of NT_STATUS_ACCESS_DENIED is an anonymous foothold to be looted.

Each lead is:
  * SURFACED the instant it is first seen — injected into the tool result so the model
    cannot scroll past it ("you observed X; you have NOT extracted it"), and
  * a GATE on giving up — declare_stuck and the loop-detector force-stops route through
    it, so the model can't "call it a day" with named loot unread.

A lead is RESOLVED when the model actually pulls/reads it: download (get/mget), cat,
read_file on the saved path, or a tool that consumes the contents (gpp-decrypt,
keepass2john, john). The ledger is the harness's; it is heuristic but BOUNDED at the
gate — it redirects, it never traps (see Agent._lead_redirect), so a file that genuinely
cannot be retrieved can't deadlock the run.
"""

import re


# (regex, label, why/next-step hint). Filenames matched case-insensitively anywhere in a
# command's output. Every entry is a file whose CONTENTS are directly loot — not merely
# "interesting" — so surfacing it and gating give-ups on it is justified.
LOOT_PATTERNS = [
    (r"groups\.xml",
        "GPP groups.xml",
        "download it and run `gpp-decrypt <cpassword>` — the AES key is public, so this is domain creds"),
    (r"(?:scheduledtasks|services|printers|drives|datasources)\.xml",
        "GPP preferences XML",
        "may carry a cpassword — download and gpp-decrypt it"),
    (r"unattend(?:ed)?\.xml",
        "unattend.xml",
        "Windows answer file — frequently holds a base64 local-admin password"),
    (r"autounattend\.xml",
        "autounattend.xml",
        "Windows answer file — frequently holds a base64 local-admin password"),
    (r"sysprep\.(?:xml|inf)",
        "sysprep answer file",
        "often a plaintext/base64 local-admin password"),
    (r"web\.config",
        "web.config",
        "ASP.NET config — connection strings, machineKey, embedded creds"),
    (r"wp-config\.php",
        "wp-config.php",
        "WordPress DB credentials and secret keys"),
    (r"\.env\b",
        ".env",
        "application secrets — DB creds, API keys, app secret"),
    (r"id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)\b",
        "SSH private key",
        "pull it, chmod 600, and `ssh -i` in as its owner"),
    (r"\.kdbx?\b",
        "KeePass database",
        "crack offline with keepass2john then john/hashcat"),
    (r"\.git-credentials\b",
        ".git-credentials",
        "plaintext git credentials"),
    (r"\.htpasswd\b",
        ".htpasswd",
        "hashed basic-auth creds — crackable with john/hashcat"),
]

# Retrieval verbs: when one appears in the SAME command as a tracked filename, the model
# is pulling/reading it, not just listing it — that resolves the loot lead. `ls`, `recurse`,
# `find`, `grep` are intentionally NOT here: enumerating is not extracting.
_RETRIEVE = re.compile(
    r"\b(?:get|mget|getfile|cat|cp|scp|sftp|download|less|more|strings|xxd|base64|"
    r"gpp-decrypt|keepass2john|john|openssl)\b", re.I)

# smbclient //host/SHARE … — captures the share name. The -L form (list shares) is excluded
# by the caller; this is the per-share access form.
_SHARE_CMD = re.compile(r"smbclient\s+//[^/\s]+/([^\s'\";]+)", re.I)
_SMB_DENIED = re.compile(r"NT_STATUS_(?:ACCESS_DENIED|LOGON_FAILURE|BAD_NETWORK_NAME)", re.I)


class LeadTracker:
    def __init__(self):
        self.leads = []          # list of dicts: kind, label, hint, match/share, resolved
        self._seen = set()       # (kind, key) already tracked — keeps observe() idempotent

    # ── detection ────────────────────────────────────────────────
    def observe(self, command: str, output: str) -> list:
        """Scan a command's OUTPUT for new high-value leads. Returns the NEWLY-added leads
        (for surfacing). A lead already tracked is not re-added, so re-listing a share won't
        re-raise it. Call this BEFORE note_command so a list-then-this-turn never both adds
        and the next-turn read resolves cleanly."""
        new = []
        text = output or ""

        # 1) known-loot filenames anywhere in the output
        for pat, label, hint in LOOT_PATTERNS:
            for m in re.finditer(pat, text, re.I):
                fname = m.group(0)
                key = ("loot", fname.lower())
                if key in self._seen:
                    continue
                self._seen.add(key)
                lead = {"kind": "loot", "match": fname, "label": label,
                        "hint": hint, "resolved": False}
                self.leads.append(lead)
                new.append(lead)

        # 2) a confirmed-readable SMB share
        share = self._readable_share(command, text)
        if share:
            key = ("share", share.lower())
            if key not in self._seen:
                self._seen.add(key)
                lead = {"kind": "share", "share": share,
                        "label": f"readable SMB share {share}",
                        "hint": "anonymous-readable — recurse-list it and download every file before pivoting",
                        "resolved": False}
                self.leads.append(lead)
                new.append(lead)

        return new

    def _readable_share(self, command: str, output: str):
        """A share is a confirmed lead only when an smbclient access (not -L list) returned an
        actual directory listing rather than an access-denied. The 'blocks of size' footer and
        the './..' dir entries are smbclient's success markers."""
        if not command or " -l" in f" {command.lower()}" or "-L" in command:
            return None
        m = _SHARE_CMD.search(command)
        if not m:
            return None
        share = m.group(1)
        if share.upper().startswith("IPC$"):
            return None
        if _SMB_DENIED.search(output):
            return None
        if "blocks of size" in output or re.search(r"\n\s+\.\.?\s+D", output):
            return share
        return None

    # ── resolution ───────────────────────────────────────────────
    def note_command(self, command: str):
        """Mark leads resolved from a retrieval/extraction command. Called for every
        run_command (after observe)."""
        c = (command or "").lower()
        # gpp-decrypt means the cpassword has been extracted — resolves every GPP-xml lead,
        # regardless of whether the filename is in this particular command.
        gpp = "gpp-decrypt" in c
        has_retrieve = bool(_RETRIEVE.search(command or ""))
        for lead in self.leads:
            if lead["resolved"]:
                continue
            if lead["kind"] == "loot":
                if gpp and "gpp" in lead["label"].lower():
                    lead["resolved"] = True
                elif has_retrieve and lead["match"].lower() in c:
                    lead["resolved"] = True
            elif lead["kind"] == "share":
                # Resolved by DOWNLOADING from the share (get/mget) — a recurse-`ls` is still just
                # listing, not extraction, so it does NOT resolve.
                if lead["share"].lower() in c and re.search(r"\b(?:mget|get)\b", c):
                    lead["resolved"] = True

    def note_read(self, path: str):
        """A read_file on a path resolves any loot lead whose filename appears in it."""
        p = (path or "").lower()
        for lead in self.leads:
            if not lead["resolved"] and lead["kind"] == "loot" and lead["match"].lower() in p:
                lead["resolved"] = True

    # ── queries ──────────────────────────────────────────────────
    def open_unresolved(self) -> list:
        return [l for l in self.leads if not l["resolved"]]

    def alert_text(self, leads: list) -> str:
        """The in-your-face note injected into the tool result the moment a lead is seen."""
        return (
            "NEW LEAD — you have OBSERVED an accessible resource but have NOT extracted it. "
            "Seeing a file in a listing is not the same as reading it. Pull and read it NOW, "
            "before any other target or pivot:\n" + self._bullets(leads)
        )

    def summary(self) -> str:
        """Compact list of everything still unextracted — for the give-up gate / nudges."""
        return self._bullets(self.open_unresolved())

    @staticmethod
    def _bullets(leads: list) -> str:
        out = []
        for l in leads:
            name = f" ({l['match']})" if l.get("match") else ""
            out.append(f"• {l['label']}{name} — {l['hint']}")
        return "\n".join(out)
