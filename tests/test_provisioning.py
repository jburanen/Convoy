from __future__ import annotations

import pytest
from passlib.hash import sha512_crypt

from chkp_cpuse_orch.errors import ProvisioningError
from chkp_cpuse_orch.services.provisioning import render_gaia_user_commands


def test_renders_full_command_set_in_order() -> None:
    cmds = render_gaia_user_commands("svc-patch", "s3cret-pw!")
    assert cmds[0] == "add user svc-patch uid 2600 homedir /home/svc-patch"
    assert cmds[1] == "set user svc-patch gid 100 shell /bin/bash"  # bash → SCP works
    assert cmds[2].startswith("set user svc-patch password-hash $6$")
    assert cmds[3] == "add rba user svc-patch roles adminRole"
    assert cmds[4] == "save config"


def test_hash_verifies_and_plaintext_absent() -> None:
    password = "correct horse battery"
    cmds = render_gaia_user_commands("svc_patch", password)
    rendered = "\n".join(cmds)
    assert password not in rendered
    pw_hash = cmds[2].split("password-hash ", 1)[1]
    assert sha512_crypt.verify(password, pw_hash)
    # rounds=5000 keeps the classic $6$salt$hash format Gaia expects.
    assert "rounds=" not in pw_hash


def test_custom_uid_and_role() -> None:
    cmds = render_gaia_user_commands("ops", "longenough", uid=4321, role="monitorRole")
    assert "uid 4321" in cmds[0]
    assert cmds[3].endswith("roles monitorRole")


def test_invalid_usernames_rejected() -> None:
    for bad in ("Admin", "1abc", "a b", "user;reboot", "", "a" * 33):
        with pytest.raises(ProvisioningError, match="invalid username"):
            render_gaia_user_commands(bad, "longenough")


def test_short_password_rejected() -> None:
    with pytest.raises(ProvisioningError, match="at least 8"):
        render_gaia_user_commands("svc", "short")


def test_uid_out_of_range_rejected() -> None:
    for uid in (0, 999, 65001):
        with pytest.raises(ProvisioningError, match="uid must be"):
            render_gaia_user_commands("svc", "longenough", uid=uid)


def test_bad_role_rejected() -> None:
    with pytest.raises(ProvisioningError, match="invalid role"):
        render_gaia_user_commands("svc", "longenough", role="bad role;x")
