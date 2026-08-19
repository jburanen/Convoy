---
name: cpuse-package-id-shell-safety
description: cpuse.py's _check_id blocklists shell metacharacters, not an allowlisted charset — real CPUSE display names contain spaces
metadata:
  type: project
---

Found 2026-08-19: installing/verifying a real package failed with
`CPUSEError: suspicious package identifier` for
`"R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 40"` — a genuine
CPUSE "Display name" (the same format `parse_packages`'s `_NAME_TYPE_LINE_RE`
path already anticipated), rejected purely for containing spaces. Manual
`installer install <package>` on the host worked fine with the same name.

**Why the allowlist was wrong**: `_check_id` (`cpuse.py`) previously required
`[A-Za-z0-9._-]+` on the theory that package IDs feed a clish command line
and need shell-safety. But spaces were never actually unsafe here — the
whole `installer <verb> <id> not-interactive` string is either
`shlex.quote()`-wrapped as a single unit before `clish -c '...'` (expert
mode, `_clish`) or sent bare to a clish-only session that doesn't do
bash-style word-splitting (clish mode). Neither path tokenizes on spaces.

**Fix**: `_check_id` now blocklists actual shell metacharacters
(`;&|` backtick `$<>\"'` and newlines) instead of allowlisting a strict
charset — real display names (spaces, parens, whatever CPUSE prints) pass
through; strings that could break the quoting still don't.

**Apply this lesson generally**: when a shell-safety check's charset starts
rejecting real-world data, check what the string *actually* feeds before
tightening the allowlist further — the safety boundary may be somewhere
else entirely (here: `shlex.quote()` around the whole command, and a
non-bash remote shell), making the "safe" charset overly conservative
rather than correct.
