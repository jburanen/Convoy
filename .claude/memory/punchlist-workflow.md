---
name: punchlist-workflow
description: When a fix closes a README Punch List item, move it to CHANGELOG.md with the shipping version, in the same commit
metadata:
  type: feedback
---

`README.md` tracks known issues under **Roadmap / Punch List** (organized by
tab/section, 🪲 marks bugs specifically). Already-fixed ones live in
**`CHANGELOG.md`** at the repo root — newest first, one `## vX.Y.Z` section per
entry. It used to be a "Squashed Bugs" section inside README.md; moved out
2026-08-27 (operator-directed) once it had grown to 42 entries and dwarfed the
forward-looking list it sat under. README keeps a pointer to it.

**Whenever a fix in this session closes something listed in the Punch List**
(check the list — a bug report from the operator often already has a 🪲 entry
there, verbatim or close to it):
1. Remove that line from its Punch List subsection.
2. Add a `## vX.Y.Z` section at the **top of `CHANGELOG.md`**, using the version
   this fix is shipping as (see [[git-workflow]]'s version-bump rule — same
   version that goes in `__version__` and the commit subject). Phrase it as what
   was wrong and the effect, similar length/tone to the existing entries — not a
   copy of the Punch List's terse one-liner, and not the full commit message.
3. Both edits ride in the **same commit** as the fix and the version bump —
   never a follow-up commit.

**Why:** operator-directed 2026-07-31, after two bugs got fixed and pushed
(commit messages only) without the Punch List being touched at all — the
README's own bug-tracking system silently drifted out of sync with reality.

**How to apply:** before wrapping up any bug-fix batch, grep `README.md` for
matching Punch List language before writing the "done" summary — don't rely on
remembering it was there. If the fix doesn't correspond to any listed item
(a bug the operator reported that was never on the Punch List), no README
change is needed — this workflow only applies to items that were already
tracked there. See [[git-workflow]] for the commit/push gating this rides
alongside (don't commit any of this unless the operator asked for *this*
batch).
