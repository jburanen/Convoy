---
name: provisioning-command-order
description: Gaia clish command ordering constraint in render_gaia_user_commands — RBA role must be assigned before the shell is changed to bash
metadata:
  type: project
---

In `render_gaia_user_commands` ([[architecture]] — `services/provisioning.py`), the
`add rba user <username> roles <role>` command must run **before**
`set user <username> gid 100 shell /bin/bash`, not after.

**Why:** the RBA role has to be applied while the account still has its default
(clish) shell; once the shell is switched to bash, applying the role no longer
works as expected. This ordering constraint was reported directly by the user
after reviewing the generated command sequence.

**How to apply:** if this function (or its command list) is touched again, keep
`add rba user ... roles ...` immediately after the password-hash line and before
the `shell /bin/bash` line. The corresponding index assertions in
`tests/test_provisioning.py` and `tests/test_web_api.py` encode this order —
update both together if it changes again.
