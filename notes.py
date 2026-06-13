"""
Persistent findings scratchpad, owned entirely by the model.

The model decides what is worth recording via note_finding / update_plan, and
reviews it via read_notes. State is persisted to a file ON KALI (over SFTP), so:
  * it survives conversation/context compaction — the model can re-read its own
    findings instead of re-deriving them from scratch, and
  * you get a human-readable engagement log on the box.

The harness never writes interpretation here. It only persists what the model
chooses to record. The memory is the harness's; the mind is the model's.
"""

import datetime
import re


class Notes:
    def __init__(self, ssh_client, path="/tmp/ctf_notes.md", target="", domain=""):  # path overridden at runtime
        self.client = ssh_client
        self.path = path
        self.is_resume = False  # set before _init_file in case it raises
        self._init_file(target, domain)

    def _sftp(self):
        return self.client.open_sftp()

    def _init_file(self, target, domain=""):
        target_line = f"Target: {target}" + (f" ({domain})" if domain else "") + "\n"
        header = (
            f"# CTF Engagement Notes\n"
            f"{target_line}"
            f"Started: {datetime.datetime.now().isoformat(timespec='seconds')}\n\n"
            f"## Progress Checklist\n"
            f"- [ ] Recon: all ports scanned\n"
            f"- [ ] Enumerate: services fingerprinted\n"
            f"- [ ] Research: exploit path identified\n"
            f"- [ ] Foothold: initial access gained\n"
            f"- [ ] User flag: captured\n"
            f"- [ ] Post-exploit: box enumerated from inside\n"
            f"- [ ] Root: privilege escalated, root flag captured\n\n"
            f"## Plan\n_(none yet — call update_plan after initial recon)_\n\n"
            f"## Findings\n"
        )
        try:
            sftp = self._sftp()
            # Resume detection: if the file already contains engagement notes, don't overwrite.
            try:
                with sftp.open(self.path, "r") as f:
                    existing = f.read().decode("utf-8", "replace")
                if existing.strip() and "CTF Engagement Notes" in existing:
                    self.is_resume = True
                    sftp.close()
                    return
            except IOError:
                pass  # file doesn't exist — create fresh
            with sftp.open(self.path, "w") as f:
                f.write(header)
            sftp.close()
        except Exception:
            pass

    def add(self, category: str, note: str) -> dict:
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        line = f"- [{stamp}] **{category}**: {note}\n"
        try:
            sftp = self._sftp()
            # append
            try:
                with sftp.open(self.path, "r") as f:
                    existing = f.read().decode("utf-8", "replace")
            except Exception:
                existing = ""
            with sftp.open(self.path, "w") as f:
                f.write(existing + line)
            sftp.close()
            return {"status": "recorded", "category": category}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def update_plan(self, plan: str) -> dict:
        """Replace the content under the '## Plan' heading."""
        try:
            sftp = self._sftp()
            with sftp.open(self.path, "r") as f:
                content = f.read().decode("utf-8", "replace")
            stamp = datetime.datetime.now().strftime("%H:%M:%S")
            new_plan_block = f"## Plan\n_(updated {stamp})_\n{plan}\n"
            if "## Plan" in content and "## Findings" in content:
                head, rest = content.split("## Plan", 1)
                _, findings = rest.split("## Findings", 1)
                content = head + new_plan_block + "\n## Findings" + findings
            else:
                content += "\n" + new_plan_block
            with sftp.open(self.path, "w") as f:
                f.write(content)
            sftp.close()
            return {"status": "plan updated"}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def read(self) -> dict:
        try:
            sftp = self._sftp()
            with sftp.open(self.path, "r") as f:
                content = f.read().decode("utf-8", "replace")
            sftp.close()
            return {"notes": content}
        except Exception as e:
            return {"notes": "", "error": str(e)}

    def mark_progress(self, item: str) -> None:
        """Check off an item in the Progress Checklist section (e.g. 'User flag', 'Root')."""
        try:
            sftp = self._sftp()
            with sftp.open(self.path, "r") as f:
                content = f.read().decode("utf-8", "replace")
            updated = re.sub(
                rf"- \[ \] ({re.escape(item)}[^\n]*)",
                r"- [x] \1",
                content,
            )
            if updated != content:
                with sftp.open(self.path, "w") as f:
                    f.write(updated)
            sftp.close()
        except Exception:
            pass
