"""
Loop / no-progress detection.

Two complementary signals tell us the agent is spinning rather than making
progress. Both are about *repetition*, not about whether notes were written —
researching (web_search/web_fetch), enumerating, and trying new commands are all
progress, even if no note is recorded for a while.

1. Repeated failing approach — each command is normalised to a "fingerprint" that
   ignores volatile bits (target IP, output paths, thread/timing flags, wordlist
   path), so 'gobuster dir -u X -w small.txt' and the same with '-t 40' count as
   the SAME approach. If one fingerprint fails repeatedly, that's a loop — even
   when the literal command strings differ.

2. No NEW distinct actions — we track the fingerprints of recent actions
   (commands AND searches/fetches). If, over a window, the model produces no
   action it hasn't already done in that window — i.e. it's only recycling the
   same handful of distinct actions — it's circling. A genuinely new search,
   fetch, or command resets this. This catches wandering that fingerprinting of
   *failures* alone misses, WITHOUT punishing productive research.

The harness nudges once when a signal trips; if the same problem persists after
the nudge, it forces the model to stop (declare_stuck).
"""

import re


class LoopDetector:
    def __init__(self, loop_threshold=3, stale_window=10, empty_research_threshold=4,
                 tool_fail_threshold=4, cycle_repeats=3, max_cycle_period=6,
                 novelty_window=12, novelty_floor=3):
        self.loop_threshold = loop_threshold
        # stale_window: how many recent actions to look across when deciding the
        # model is only recycling old actions and producing nothing new.
        self.stale_window = stale_window
        # cycle detection: a block of `period` actions repeating `cycle_repeats` times
        # contiguously at the tail is a multi-step loop (navigate→fill→submit→…). The
        # stale signal misses this because each step is "new" vs the previous one, so it
        # keeps resetting — but the BLOCK as a whole is pure non-progress.
        self.cycle_repeats = cycle_repeats
        self.max_cycle_period = max_cycle_period
        # low-novelty window: ORDER-INDEPENDENT churn signal. Over the last `novelty_window`
        # substantive actions, count DISTINCT ones. The stale & cycle signals are both dodged
        # by inserting trivially-varied filler (re-greps, re-navigations) between repeats; this
        # isn't, because it just counts variety. Empirically the legit runs never drop below ~5
        # distinct in a 12-window while the stuck silentium runs sit at 2 — so floor=3 separates
        # them with a 2-distinct margin and catches BOTH the clean and the messy-interrupted loops.
        self.novelty_window = novelty_window
        self.novelty_floor = novelty_floor
        # empty_research_threshold: consecutive empty web/github searches before we
        # call it a no-progress research spin (text-independent — see record_research).
        self.empty_research_threshold = empty_research_threshold
        # tool_fail_threshold: consecutive errors/timeouts on one channel (browser/web)
        # before we call it a dead channel (see record_tool_outcome).
        self.tool_fail_threshold = tool_fail_threshold

        self.fail_counts = {}            # fingerprint -> consecutive failure count
        self.nudged_fingerprints = set() # fingerprints we've nudged about

        self.recent = []                 # fingerprints of recent actions (rolling)
        self.actions_since_new = 0       # consecutive actions that were NOT new
        self.nudged_stale = False

        self.action_history = []         # longer fingerprint history, for cycle detection
        self.nudged_cycle = False

        self.novelty_recent = []         # rolling fingerprints for the low-novelty signal
        self.nudged_novelty = False

        self.empty_research = 0          # consecutive research calls that returned nothing
        self.nudged_empty = False

        self.tool_outcomes = []          # rolling window of recent channel-tool outcomes (True=failed)
        self.nudged_toolfail = False

    # ── command / action normalisation ──────────────────────────
    # words that carry no distinguishing meaning in a search query, so two queries
    # that differ only by these are really the SAME search reworded.
    _STOPWORDS = {
        "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with",
        "is", "are", "any", "some", "common", "general", "known", "possible",
        "potential", "related", "about", "issue", "issues", "problem", "problems",
        "vuln", "vulns", "vulnerability", "vulnerabilities", "security",
        "misconfiguration", "misconfigurations", "find", "search", "check",
    }

    @classmethod
    def fingerprint(cls, command: str) -> str:
        c = command.strip()
        c = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", c)
        c = re.sub(r"https?://\S+", "<URL>", c)
        c = re.sub(r"\s-o\w*\s+\S+", " ", c)
        c = re.sub(r"\s>\s*\S+", " ", c)
        c = re.sub(r"\s-t\s*\d+", " ", c)
        c = re.sub(r"\s--threads\s*\d+", " ", c)
        c = re.sub(r"\s-(?:T|p|w|W|r|R)\s*\S+", " ", c)
        c = re.sub(r"\s--(?:rate|timeout|wait|delay|max-time|connect-timeout|retry|retry-delay)\s*\S+", " ", c)
        c = re.sub(r"\s-m\s*\d+", " ", c)   # curl -m <seconds>
        c = re.sub(r"\s\S+\.(?:txt|lst)\b", " <WORDLIST>", c)
        c = re.sub(r"\s+", " ", c).strip().lower()
        tokens = c.split(" ")

        # For searches: reduce to a SEMANTIC fingerprint — drop generic filler
        # words and sort the remaining meaningful terms — so "Next.js common
        # vulnerabilities", "Next.js vulnerability", and "vulnerabilities in Next.js"
        # all collapse to the same fingerprint. Genuinely different searches (new
        # CVE id, a specific technique/component, a product name) still differ.
        if tokens and tokens[0] == "web_search:":
            terms = tokens[1:]
            terms = [re.sub(r"[^\w.\-]", "", t) for t in terms]   # strip punctuation
            meaningful = sorted(set(t for t in terms if t and t not in cls._STOPWORDS))
            return "web_search: " + " ".join(meaningful)
        if tokens and tokens[0] == "web_fetch:":
            return " ".join(tokens[:12])   # urls already normalised to <URL>+path
        # Command path: collapse bare port-like integers (2–5 digits) so re-running the SAME
        # exploit/payload with only the port changed — 4444 → 4446 → 4449 → 4450 — is ONE
        # fingerprint, not a brand-new "approach" each time. Without this a port-incrementing
        # retry loop dodges the repeat detector entirely (observed live: a self-listening PoC
        # re-fired on climbing ports while the listener never moved). Flag-attached ports
        # (-p/-t/-m/-T) and URL host:port are already stripped/normalised above, and this runs
        # ONLY here — NOT on web_search/web_fetch, where 2–5 digit tokens are CVE ids / versions.
        toks = [re.sub(r"\b\d{2,5}\b", "<PORT>", t) for t in tokens[:6]]
        return " ".join(toks)

    @classmethod
    def _cycle_key(cls, action_repr: str) -> str:
        """Identity of an action for CYCLE detection. Unlike fingerprint(), this PRESERVES the
        target (url host+path, selector, command shape) so visiting three DIFFERENT pages reads
        as three distinct actions — only REVISITING the same targets in the same order looks like
        a cycle. Strips scheme/query/volatile timing and lowercases so trivial respellings collapse."""
        c = action_repr.strip()
        c = re.sub(r"https?://", "", c)        # keep host+path, drop scheme
        c = re.sub(r"\?\S*", "", c)            # drop query string
        c = re.sub(r"\s-(?:t|T|p|w|m)\s*\S+", " ", c)   # volatile thread/port/wordlist/timeout flags
        c = re.sub(r"\s+", " ", c).strip().lower()
        return c[:80]

    # ── signal 1: repeated failing approach ──────────────────────
    def record_command(self, command: str, failed: bool) -> dict:
        fp = self.fingerprint(command)
        if failed:
            self.fail_counts[fp] = self.fail_counts.get(fp, 0) + 1
        else:
            self.fail_counts[fp] = 0
        count = self.fail_counts.get(fp, 0)
        return {
            "loop": count >= self.loop_threshold,
            "fingerprint": fp,
            "count": count,
            "already_nudged": fp in self.nudged_fingerprints,
        }

    # ── signal 2: no new distinct actions ────────────────────────
    def record_action(self, action_repr: str):
        """Record ANY substantive action (command, search, fetch). Decides whether
        it was 'new' (not seen in the recent window) or a recycle."""
        fp = self.fingerprint(action_repr)
        is_new = fp not in self.recent
        if is_new:
            self.actions_since_new = 0
            self.nudged_stale = False
        else:
            self.actions_since_new += 1

        self.recent.append(fp)
        if len(self.recent) > self.stale_window:
            self.recent.pop(0)

        # Cycle history uses a DIFFERENT key (see _cycle_key): it preserves the navigation
        # target (url path / selector), because fingerprint() collapses every URL to <URL> —
        # which would make visiting three DIFFERENT pages look like a loop. A target not seen
        # in the recent block means we've moved to new ground, so any cycle (and its nudge) is
        # broken: clear the nudge so a later, unrelated cycle gets its own nudge-then-force.
        ckey = self._cycle_key(action_repr)
        if ckey not in self.action_history[-self.max_cycle_period:]:
            self.nudged_cycle = False
        self.action_history.append(ckey)
        keep = self.max_cycle_period * (self.cycle_repeats + 1)
        if len(self.action_history) > keep:
            self.action_history.pop(0)

        self.novelty_recent.append(fp)
        if len(self.novelty_recent) > self.novelty_window:
            self.novelty_recent.pop(0)
        # Re-arm the novelty nudge once the model diversifies again (escaped the churn).
        if len(set(self.novelty_recent)) > self.novelty_floor:
            self.nudged_novelty = False

    def low_novelty(self) -> dict:
        """Order-INDEPENDENT churn signal: over the last `novelty_window` substantive actions,
        how many are DISTINCT? A model circling a small set of targets — even while inserting
        trivially-varied filler that keeps the consecutive stale/cycle signals resetting — shows
        very few distinct actions per window. Only evaluated once the window is full."""
        w = self.novelty_recent
        distinct = len(set(w))
        tripped = len(w) >= self.novelty_window and distinct <= self.novelty_floor
        return {"low_novelty": tripped, "distinct": distinct, "already_nudged": self.nudged_novelty}

    def mark_nudged_novelty(self):
        self.nudged_novelty = True

    def cycle(self) -> dict:
        """Detect a repeating multi-step CYCLE at the tail of the action history — e.g.
        navigate→fill→submit→navigate→fill→submit…. Finds the SHORTEST period p (2..max)
        whose block repeats at least `cycle_repeats` times contiguously at the end. Requires
        ≥2 distinct actions in the block, since a single action repeating is already covered
        by the stale / failing-approach signals."""
        h = self.action_history
        for p in range(2, self.max_cycle_period + 1):
            need = p * self.cycle_repeats
            if len(h) < need:
                continue
            tail = h[-need:]
            block = tail[:p]
            if len(set(block)) >= 2 and all(tail[i] == block[i % p] for i in range(need)):
                return {
                    "cycle": True,
                    "period": p,
                    "reps": self.cycle_repeats,
                    "already_nudged": self.nudged_cycle,
                }
        return {"cycle": False, "period": 0, "reps": 0, "already_nudged": self.nudged_cycle}

    def mark_nudged_cycle(self):
        self.nudged_cycle = True

    def stale(self) -> dict:
        tripped = self.actions_since_new >= self.stale_window
        return {
            "stale": tripped,
            "count": self.actions_since_new,
            "already_nudged": self.nudged_stale,
        }

    # ── signal 3: research returning nothing ─────────────────────
    def record_research(self, empty: bool) -> dict:
        """Track consecutive research calls (web/github search) that came back empty.
        Text-INDEPENDENT, unlike signal 2's fingerprint: it catches a model rewording
        the same dead query over and over — distinct fingerprints, zero progress — which
        is exactly the pattern that slips past staleness detection."""
        if empty:
            self.empty_research += 1
        else:
            self.empty_research = 0
            self.nudged_empty = False
        return {
            "empty_loop": self.empty_research >= self.empty_research_threshold,
            "count": self.empty_research,
            "already_nudged": self.nudged_empty,
        }

    # ── signal 4: a channel tool failing over and over ───────────
    def record_tool_outcome(self, failed: bool) -> dict:
        """Track failures of a CHANNEL tool (browser / web_fetch) over a SLIDING WINDOW, not
        strictly consecutively. A flaky channel (the headless browser timing out) is typically
        INTERLEAVED with the odd success — fill(timeout) → navigate(ok) → fill(timeout) →
        get_content(ok) → fill(timeout) — and a consecutive counter resets to zero on each success,
        so the model rides the dead channel forever (seen live: 5 browser_fill timeouts dodged the
        consecutive signal because successful navigate/get_content calls kept resetting it).
        Counting fails within the last `2*threshold` outcomes is interleave-proof. A window that
        clears (≤1 fail) re-arms the nudge so a genuinely recovered channel isn't penalised."""
        self.tool_outcomes.append(bool(failed))
        win = max(2, self.tool_fail_threshold * 2)
        if len(self.tool_outcomes) > win:
            self.tool_outcomes.pop(0)
        fails = sum(self.tool_outcomes)
        # Trip only when the window holds enough failures AND the channel is STILL failing right now
        # (last outcome failed). This separates "4 fails then 4 successes" (recovering — must NOT trip,
        # or we'd force-stop a channel the model just got working again) from "4 fails, still failing".
        tripped = fails >= self.tool_fail_threshold and bool(self.tool_outcomes[-1])
        if fails <= 1:
            self.nudged_toolfail = False    # window cleared → channel recovered → re-arm the nudge
        return {
            "fail_loop": tripped,
            "count": fails,
            "window": len(self.tool_outcomes),
            "already_nudged": self.nudged_toolfail,
        }

    # ── operator intervention ────────────────────────────────────
    def reset_after_intervention(self):
        """Clear every trip counter, nudge flag, and action buffer. Called when the operator
        steps in at a stuck point and hands the model new direction: the prior spin is no longer
        the situation, so the detector starts from a clean slate instead of immediately re-firing
        the same force-stop on a window that hasn't turned over yet."""
        self.fail_counts.clear()
        self.nudged_fingerprints.clear()
        self.recent.clear()
        self.actions_since_new = 0
        self.nudged_stale = False
        self.action_history.clear()
        self.nudged_cycle = False
        self.novelty_recent.clear()
        self.nudged_novelty = False
        self.empty_research = 0
        self.nudged_empty = False
        self.tool_outcomes.clear()
        self.nudged_toolfail = False

    # ── nudge bookkeeping ────────────────────────────────────────
    def mark_nudged_loop(self, fingerprint: str):
        self.nudged_fingerprints.add(fingerprint)

    def mark_nudged_stale(self):
        self.nudged_stale = True

    def mark_nudged_empty(self):
        self.nudged_empty = True

    def mark_nudged_toolfail(self):
        self.nudged_toolfail = True
