from __future__ import annotations

import shlex

import pytest
from passlib.hash import sha512_crypt

from chkp_cpuse_orch.errors import ProvisioningError
from chkp_cpuse_orch.services.provisioning import (
    parse_api_key_from_add_api_key_output,
    render_add_administrator_command,
    render_add_api_key_command,
    render_bootstrap_script,
    render_gaia_user_commands,
    render_mgmt_api_commands,
    render_mgmt_login_command,
    render_publish_logout_commands,
    render_set_api_settings_command,
    render_show_administrator_command,
    render_spark_admin_commands,
)


def test_renders_full_command_set_in_order() -> None:
    cmds = render_gaia_user_commands("svc-patch", "s3cret-pw!")
    assert cmds[0] == "add user svc-patch uid 0 homedir /home/svc-patch"
    assert cmds[1].startswith("set user svc-patch password-hash $6$")
    assert cmds[2] == "add rba user svc-patch roles adminRole"
    assert cmds[3] == "set user svc-patch gid 100"  # clish stays the default login shell
    assert cmds[4] == "save config"


def test_hash_verifies_and_plaintext_absent() -> None:
    password = "correct horse battery"
    cmds = render_gaia_user_commands("svc_patch", password)
    rendered = "\n".join(cmds)
    assert password not in rendered
    pw_hash = cmds[1].split("password-hash ", 1)[1]
    assert sha512_crypt.verify(password, pw_hash)
    # rounds=5000 keeps the classic $6$salt$hash format Gaia expects.
    assert "rounds=" not in pw_hash


def test_custom_uid_and_role() -> None:
    cmds = render_gaia_user_commands("ops", "longenough", uid=4321, role="monitorRole")
    assert "uid 4321" in cmds[0]
    assert cmds[2].endswith("roles monitorRole")


def test_render_bootstrap_script_wraps_every_command_in_clish_dash_c() -> None:
    # render_gaia_user_commands salts its hash randomly each call, so this
    # doesn't compare against a second independent call — it checks the
    # wrapping shape of render_bootstrap_script's own single output instead.
    script = render_bootstrap_script("svc-patch", "s3cret-pw!")
    lines = script.split("\n")
    assert lines[0] == "clish -c 'add user svc-patch uid 0 homedir /home/svc-patch'"
    assert lines[1].startswith("clish -c 'set user svc-patch password-hash $6$")
    assert lines[1].endswith("'")
    assert lines[2] == "clish -c 'add rba user svc-patch roles adminRole'"
    assert lines[3] == "clish -c 'set user svc-patch gid 100'"
    assert lines[4] == "clish -c 'save config'"


def test_render_bootstrap_script_quotes_shell_metacharacters_safely() -> None:
    # password-hash's $6$salt$hash contains characters a naive wrapper could
    # mangle if passed to bash unquoted — shlex.quote must protect it.
    script = render_bootstrap_script("svc-patch", "correct horse battery")
    for line in script.split("\n"):
        assert line.startswith("clish -c ")
        # Every wrapped command round-trips through shlex back to the original.
        (inner,) = shlex.split(line[len("clish -c ") :])
        assert "\n" not in inner


def test_invalid_usernames_rejected() -> None:
    for bad in ("Admin", "1abc", "a b", "user;reboot", "", "a" * 33):
        with pytest.raises(ProvisioningError, match="invalid username"):
            render_gaia_user_commands(bad, "longenough")


def test_short_password_rejected() -> None:
    with pytest.raises(ProvisioningError, match="at least 8"):
        render_gaia_user_commands("svc", "short")


def test_uid_out_of_range_rejected() -> None:
    for uid in (-1, 65001):
        with pytest.raises(ProvisioningError, match="uid must be"):
            render_gaia_user_commands("svc", "longenough", uid=uid)


def test_uid_zero_allowed() -> None:
    # Some adminRole accounts are uid 0 — the operator must be able to mirror
    # that when provisioning this service account.
    cmds = render_gaia_user_commands("svc", "longenough", uid=0)
    assert "uid 0" in cmds[0]


def test_bad_role_rejected() -> None:
    with pytest.raises(ProvisioningError, match="invalid role"):
        render_gaia_user_commands("svc", "longenough", role="bad role;x")


# -- render_spark_admin_commands (Quantum Spark / SMB clish) ----------------------


def test_spark_renders_single_add_administrator_command() -> None:
    cmds = render_spark_admin_commands("svc-patch", "s3cret-pw!")
    assert len(cmds) == 1
    assert cmds[0].startswith("add administrator username svc-patch password-hash $6$")
    assert cmds[0].endswith('permission "Super Admin"')


def test_spark_hash_verifies_and_plaintext_absent() -> None:
    password = "correct horse battery"
    (cmd,) = render_spark_admin_commands("svc_patch", password)
    assert password not in cmd
    pw_hash = cmd.split("password-hash ", 1)[1].split(" permission", 1)[0]
    assert sha512_crypt.verify(password, pw_hash)
    assert "rounds=" not in pw_hash  # classic $6$salt$hash, matching cryptpw -a sha512


def test_spark_custom_permission() -> None:
    (cmd,) = render_spark_admin_commands("ops", "longenough", permission="read-write")
    assert cmd.endswith('permission "read-write"')


def test_spark_invalid_usernames_rejected() -> None:
    for bad in ("Admin", "1abc", "a b", "user;reboot", "", "a" * 33):
        with pytest.raises(ProvisioningError, match="invalid username"):
            render_spark_admin_commands(bad, "longenough")


def test_spark_short_password_rejected() -> None:
    with pytest.raises(ProvisioningError, match="at least 8"):
        render_spark_admin_commands("svc", "short")


def test_spark_bad_permission_rejected() -> None:
    with pytest.raises(ProvisioningError, match="invalid permission"):
        render_spark_admin_commands("svc", "longenough", permission="root")


def test_mgmt_api_commands_single_session_and_api_key() -> None:
    cmds = render_mgmt_api_commands("svc-patch")
    joined = "\n".join(cmds)
    # One login → session file reused for every mutation → published in that session.
    # SMS logins must target "System Data" or add administrator/add api-key fail
    # with err_inappropriate_domain_type.
    assert cmds[0].startswith('mgmt_cli login -r true --domain "System Data" > ')
    assert 'authentication-method "api key"' in joined
    assert 'permissions-profile "Super User"' in joined
    # The administrator only sets the auth method; the key itself comes from a
    # separate `add api-key` call so it can be printed in its own JSON output.
    assert "add api-key admin-name svc-patch --format json" in joined
    assert any(c.endswith("publish") for c in cmds)
    assert cmds[-1].startswith("rm -f ")
    # No restart: not needed for an administrator/api-key add to take effect.
    assert not any("restart" in c for c in cmds)
    # Every mutating call reuses the one session file (so the add is published).
    session_calls = [c for c in cmds if c.startswith("mgmt_cli -s ")]
    assert len({c.split()[2] for c in session_calls}) == 1
    # The API-settings change was removed — the operator manages that separately.
    assert not any("accepted-api-calls-from" in c for c in cmds)


def test_mgmt_api_rejects_bad_username() -> None:
    with pytest.raises(ProvisioningError, match="invalid username"):
        render_mgmt_api_commands("Bad Name")


def test_mgmt_api_commands_use_multi_domain_profile_for_mds() -> None:
    cmds = render_mgmt_api_commands("svc-patch", is_mds=True)
    joined = "\n".join(cmds)
    assert 'multi-domain-profile "Multi-Domain Super User"' in joined
    assert "add administrator" in joined
    # The single-domain form must not also appear.
    assert "permissions-profile" not in joined.replace("multi-domain-profile", "")
    # The System Data domain flag is SMS-specific (unconfirmed on live MDS gear);
    # the MDS login is left as a plain root login.
    assert "--domain" not in cmds[0]


# -- composable command builders (used directly by connect_primary.py's
# idempotent run, unlike render_mgmt_api_commands' flat "assume-fresh" preview) --


def test_composable_builders_match_the_flat_preview() -> None:
    """The idempotent run's building blocks must render byte-identical
    commands to the flat preview (minus the show-administrator probe, which
    only the idempotent run needs)."""
    flat = render_mgmt_api_commands("svc-patch", is_mds=False)
    composed = [
        render_mgmt_login_command(is_mds=False),
        render_add_administrator_command("svc-patch", is_mds=False),
        render_add_api_key_command("svc-patch"),
        *render_publish_logout_commands(),
    ]
    assert flat == composed


def test_show_administrator_command_rejects_bad_username() -> None:
    with pytest.raises(ProvisioningError, match="invalid username"):
        render_show_administrator_command("Bad Name")


def test_show_administrator_command_uses_same_session_file_as_login() -> None:
    login = render_mgmt_login_command(is_mds=False)
    probe = render_show_administrator_command("svc-patch")
    session_file = login.rsplit("> ", 1)[1]
    assert f"-s {session_file}" in probe


# -- API key parsing ---------------------------------------------------------------


def test_parse_api_key_recognized_field() -> None:
    assert parse_api_key_from_add_api_key_output('{"api-key": "abc123"}') == "abc123"


def test_parse_api_key_case_insensitive_and_alternate_spellings() -> None:
    assert parse_api_key_from_add_api_key_output('{"apiKey": "abc123"}') == "abc123"
    assert parse_api_key_from_add_api_key_output('{"API-KEY": "abc123"}') == "abc123"
    assert parse_api_key_from_add_api_key_output('{"value": "abc123"}') == "abc123"


def test_parse_api_key_prefers_first_candidate_field() -> None:
    assert (
        parse_api_key_from_add_api_key_output('{"value": "wrong", "api-key": "right"}') == "right"
    )


def test_parse_api_key_rejects_non_json() -> None:
    with pytest.raises(ProvisioningError, match="could not parse API key") as exc:
        parse_api_key_from_add_api_key_output("not json at all")
    # The raw (possibly secret-bearing) input must never appear in the message.
    assert "not json at all" not in str(exc.value)


def test_parse_api_key_rejects_unexpected_shape() -> None:
    with pytest.raises(ProvisioningError, match="could not parse API key"):
        parse_api_key_from_add_api_key_output("[1, 2, 3]")


def test_parse_api_key_rejects_missing_field() -> None:
    with pytest.raises(ProvisioningError, match="could not parse API key"):
        parse_api_key_from_add_api_key_output('{"message": "ok, but no key here"}')


# -- set api-settings (used by services/api_access.py's 403 repair flow) ----------


def test_set_api_settings_command_widens_accepted_calls_from() -> None:
    login = render_mgmt_login_command(is_mds=False)
    cmd = render_set_api_settings_command(is_mds=False)
    session_file = login.rsplit("> ", 1)[1]
    assert cmd == (
        f"mgmt_cli -s {session_file} set api-settings accepted-api-calls-from "
        '"All IP addresses that can be used for GUI clients" --domain "System Data"'
    )


def test_set_api_settings_command_mds_omits_domain() -> None:
    cmd = render_set_api_settings_command(is_mds=True)
    assert "--domain" not in cmd
