"""The CHKP_CPUSE_* -> CONVOY_* rename must not strand a running deployment.

The operator's .env lives outside this repo, so the old names have to keep
working after a `git pull` -- most critically CHKP_CPUSE_MASTER_KEY, which
derives the credential-store key.
"""

from convoy.credentials import load_master_key
from convoy.envcompat import compat_env
from convoy.reporting import resolve_log_level
from convoy.web.auth import load_auth_settings


def test_legacy_prefix_is_visible_under_the_new_name() -> None:
    env = compat_env({"CHKP_CPUSE_MASTER_KEY": "secret"})
    assert env["CONVOY_MASTER_KEY"] == "secret"
    # the old key is still present, so nothing that reads it directly breaks
    assert env["CHKP_CPUSE_MASTER_KEY"] == "secret"


def test_new_name_wins_over_legacy() -> None:
    """An operator mid-migration may have both set; the new one must win, or a
    stale leftover would silently override the value they just added."""
    env = compat_env({"CHKP_CPUSE_MASTER_KEY": "old", "CONVOY_MASTER_KEY": "new"})
    assert env["CONVOY_MASTER_KEY"] == "new"


def test_unrelated_variables_are_untouched() -> None:
    env = compat_env({"PATH": "/usr/bin", "CHKP_OTHER": "x"})
    assert env["PATH"] == "/usr/bin"
    assert "CONVOY_OTHER" not in env


def test_master_key_still_resolves_from_the_legacy_name() -> None:
    """The load-bearing case: this is what decrypts an existing credential store."""
    assert load_master_key({"CHKP_CPUSE_MASTER_KEY": "passphrase"}) == "passphrase"


def test_log_level_still_resolves_from_the_legacy_name() -> None:
    import logging

    assert resolve_log_level({"CHKP_CPUSE_WEB_LOG_LEVEL": "DEBUG"}) == logging.DEBUG


def test_ldap_settings_still_resolve_from_the_legacy_names() -> None:
    settings = load_auth_settings(
        {
            "CHKP_CPUSE_LDAP_URL": "ldaps://dc.example.internal",
            "CHKP_CPUSE_LDAP_REQUIRED_GROUP": "CN=ops,DC=example,DC=internal",
            "CHKP_CPUSE_LDAP_USER_DN_TEMPLATE": "{username}@example.internal",
        }
    )
    assert settings is not None
    assert settings.url == "ldaps://dc.example.internal"
