"""Render Gaia clish commands that provision this tool's service account.

The operator pastes the generated commands into clish on EACH management server.
The account gets ``/bin/bash`` as its login shell — required so SCP/SFTP package
staging works (clish as a login shell blocks it). Because the shell is bash, all
CPUSE operations go through the ``clish -c`` wrapper (``GaiaShell.EXPERT``, the
default) and CDT/stat/pgrep commands run natively.

The password is embedded ONLY as a salted SHA-512 crypt hash (Gaia's
``set user ... password-hash``), so the rendered script is safe to display,
copy, and paste. Nothing here talks to a server and nothing is stored.
"""

from __future__ import annotations

import re

from passlib.hash import sha512_crypt

from ..errors import ProvisioningError

# Gaia usernames: conservative POSIX subset.
_USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_ROLE_RE = re.compile(r"[A-Za-z0-9_-]+")

_MIN_PASSWORD_LEN = 8
# 0 is allowed: Gaia's built-in superuser-equivalent admin accounts (adminRole)
# are commonly uid 0, and operators provisioning this service account to mirror
# an existing admin's privileges need to be able to enter that.
_UID_RANGE = (0, 65000)
# Default to uid 0 to match the built-in adminRole accounts this service
# account is meant to mirror; the operator can still enter any uid in range.
DEFAULT_UID = 0
DEFAULT_ROLE = "adminRole"  # full admin: CPUSE installer verbs require it


def render_gaia_user_commands(
    username: str,
    password: str,
    *,
    uid: int = DEFAULT_UID,
    role: str = DEFAULT_ROLE,
) -> list[str]:
    """Clish commands to create the service account on one management server.

    Rounds=5000 keeps the classic ``$6$salt$hash`` format (no ``rounds=``
    directive) for maximum Gaia compatibility.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(
            f"invalid username {username!r}: lowercase letters, digits, '_' and '-', "
            "starting with a letter or '_', max 32 chars"
        )
    if len(password) < _MIN_PASSWORD_LEN:
        raise ProvisioningError(f"password must be at least {_MIN_PASSWORD_LEN} characters")
    if not (_UID_RANGE[0] <= uid <= _UID_RANGE[1]):
        raise ProvisioningError(f"uid must be between {_UID_RANGE[0]} and {_UID_RANGE[1]}")
    if not _ROLE_RE.fullmatch(role):
        raise ProvisioningError(f"invalid role name: {role!r}")

    # types-passlib leaves .using() untyped; the call shape is stable.
    hasher = sha512_crypt.using(rounds=5000)  # type: ignore[no-untyped-call]
    password_hash = hasher.hash(password)
    return [
        f"add user {username} uid {uid} homedir /home/{username}",
        f"set user {username} password-hash {password_hash}",
        f"add rba user {username} roles {role}",
        f"set user {username} gid 100 shell /bin/bash",
        "save config",
    ]


PROVISIONING_NOTES = [
    "The user is created with a bash/expert shell to permit SCP transfers; the "
    "`clish -c` is used for commands as needed.",
    "The password appears only as a salted SHA-512 hash, never in plaintext.",
]


# The clish/RBA account above is a *Gaia OS* user (SSH/clish/WebUI). The Check Point
# Management API authenticates *Security Management administrators* — a separate
# account system in the management database — so it needs its own provisioning. The
# tool's estate auto-discovery uses the Management API, so an API-enabled admin (with
# an API key) is what makes discovery work.
_API_SESSION_FILE = "/tmp/cpuse_orch_mgmt_api.sid"
DEFAULT_API_PROFILE = "Super User"  # built-in profile; read access is enough for discovery
DEFAULT_MDS_API_PROFILE = "Multi-Domain Super User"  # built-in global (all-Domains) profile

# A note prefixed with this marker is rendered emphasized (orange) in the UI.
NOTE_EMPHASIS = "[!] "


def render_mgmt_api_commands(
    username: str,
    *,
    permissions_profile: str | None = None,
    is_mds: bool = False,
) -> list[str]:
    """Expert-mode commands that create a Management API administrator (API-key auth)
    on ONE Security Management Server / MDS.

    All mutations share a single ``mgmt_cli`` session so the ``add administrator`` /
    ``add api-key`` are actually published; ``-r true`` logs in as root on the box
    (no password). ``add administrator ... authentication-method "api key"`` only
    sets the auth *method* — it does not itself issue a key. The key value is
    generated (and printed once, in its JSON output) by the separate
    ``add api-key admin-name <name>`` command (CLI reference: ``add-api-key`` v2.1),
    run in the same session so it can see the not-yet-published administrator.
    The operator copies that key into the Credentials section (kind: API key).

    A Multi-Domain Server has no single-domain ``permissions-profile`` object of
    its own — a *global* administrator (one this tool's estate-wide discovery
    needs) is granted via the separate ``multi-domain-profile`` parameter instead,
    with its own distinctly-named built-in profile, ``"Multi-Domain Super User"``.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(
            f"invalid username {username!r}: lowercase letters, digits, '_' and '-', "
            "starting with a letter or '_', max 32 chars"
        )
    if permissions_profile is None:
        permissions_profile = DEFAULT_MDS_API_PROFILE if is_mds else DEFAULT_API_PROFILE
    if not _ROLE_RE.fullmatch(permissions_profile.replace(" ", "")):
        raise ProvisioningError(f"invalid permissions profile: {permissions_profile!r}")
    sid = _API_SESSION_FILE
    profile_param = "multi-domain-profile" if is_mds else "permissions-profile"
    return [
        f"mgmt_cli login -r true > {sid}",
        f"mgmt_cli -s {sid} add administrator name {username} "
        f'authentication-method "api key" {profile_param} "{permissions_profile}"',
        f"mgmt_cli -s {sid} add api-key admin-name {username} --format json",
        f"mgmt_cli -s {sid} publish",
        f"mgmt_cli -s {sid} logout",
        f"rm -f {sid}",
    ]


MGMT_API_NOTES = [
    NOTE_EMPHASIS + "`add api-key` prints the API key in its JSON output. Copy it ONCE "
    "(it cannot be retrieved later), then Edit the credential entry added below and "
    "paste it as the API key.",
]

MDS_API_NOTE = (
    "This environment is Multi-Domain: the administrator is granted the "
    '`multi-domain-profile "Multi-Domain Super User"` (a global, all-Domains '
    "profile), not the single-domain `permissions-profile` used on an SMS."
)
