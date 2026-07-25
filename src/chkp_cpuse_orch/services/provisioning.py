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

import json
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


def _validate_mgmt_api_args(username: str, permissions_profile: str | None, is_mds: bool) -> str:
    """Shared validation for the command builders below. Returns the effective
    (validated) permissions/multi-domain profile name."""
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(
            f"invalid username {username!r}: lowercase letters, digits, '_' and '-', "
            "starting with a letter or '_', max 32 chars"
        )
    if permissions_profile is None:
        permissions_profile = DEFAULT_MDS_API_PROFILE if is_mds else DEFAULT_API_PROFILE
    if not _ROLE_RE.fullmatch(permissions_profile.replace(" ", "")):
        raise ProvisioningError(f"invalid permissions profile: {permissions_profile!r}")
    return permissions_profile


def render_mgmt_login_command(*, is_mds: bool = False) -> str:
    """Log into ``mgmt_cli`` as root (no password) and save the session to a
    well-known temp file so later commands (possibly separate SSH round-trips)
    can reuse it via ``-s``.

    On a standalone SMS (``is_mds=False``), the login also passes
    ``--domain "System Data"``: without it the session lands in the box's own
    "Domain" context, where ``add administrator``/``add api-key`` fail with
    ``err_inappropriate_domain_type`` ("This command can work only on domains
    of type MDS") — operator-confirmed against live gear, 2026-07-25. Not yet
    confirmed whether the MDS path (``is_mds=True``) needs the same, so left
    untouched here.
    """
    domain_flag = "" if is_mds else ' --domain "System Data"'
    return f"mgmt_cli login -r true{domain_flag} > {_API_SESSION_FILE}"


def render_show_administrator_command(username: str) -> str:
    """Existence probe for the Management API administrator, run against the
    session opened by ``render_mgmt_login_command``. Used to decide whether
    ``add administrator`` is needed (re-running the flow to issue a fresh API
    key for an already-provisioned admin must not fail on "already exists").

    NOT YET CONFIRMED against live gear: the exact not-found shape (non-zero
    exit status vs. a JSON error body) for ``show administrator`` on an
    unknown name. Callers should treat either as "does not exist yet" until
    this is verified against a real management server.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(f"invalid username {username!r}")
    return f"mgmt_cli -s {_API_SESSION_FILE} show administrator name {username} --format json"


def render_add_administrator_command(
    username: str, *, permissions_profile: str | None = None, is_mds: bool = False
) -> str:
    """Create the Management API administrator (API-key auth method only —
    this does not itself issue a key; see ``render_add_api_key_command``).

    A Multi-Domain Server has no single-domain ``permissions-profile`` object of
    its own — a *global* administrator (one this tool's estate-wide discovery
    needs) is granted via the separate ``multi-domain-profile`` parameter instead,
    with its own distinctly-named built-in profile, ``"Multi-Domain Super User"``.
    """
    permissions_profile = _validate_mgmt_api_args(username, permissions_profile, is_mds)
    profile_param = "multi-domain-profile" if is_mds else "permissions-profile"
    return (
        f"mgmt_cli -s {_API_SESSION_FILE} add administrator name {username} "
        f'authentication-method "api key" {profile_param} "{permissions_profile}"'
    )


def render_add_api_key_command(username: str) -> str:
    """Issue a (new) API key for ``username``, printed once in its JSON output
    (CLI reference: ``add-api-key`` v2.1) — see
    ``parse_api_key_from_add_api_key_output``. Safe to re-run for an
    already-provisioned admin: each call issues a fresh key, which is exactly
    the "regenerate" path this tool relies on.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(f"invalid username {username!r}")
    return f"mgmt_cli -s {_API_SESSION_FILE} add api-key admin-name {username} --format json"


def render_publish_logout_commands() -> list[str]:
    """Publish the session's changes, log out, and remove the session file."""
    return [
        f"mgmt_cli -s {_API_SESSION_FILE} publish",
        f"mgmt_cli -s {_API_SESSION_FILE} logout",
        f"rm -f {_API_SESSION_FILE}",
    ]


def render_mgmt_api_commands(
    username: str,
    *,
    permissions_profile: str | None = None,
    is_mds: bool = False,
) -> list[str]:
    """Full "assume-fresh" command sequence that creates a Management API
    administrator (API-key auth) and issues its first API key, on ONE Security
    Management Server / MDS. All mutations share a single ``mgmt_cli`` session
    so the ``add administrator`` / ``add api-key`` are actually published.

    Used for the copy-paste-style preview shown before an automated run (see
    services/connect_primary.py) — the automated run itself skips
    ``add administrator`` when ``render_show_administrator_command`` reports
    the account already exists, which this flat preview does not model.
    """
    permissions_profile = _validate_mgmt_api_args(username, permissions_profile, is_mds)
    return [
        render_mgmt_login_command(is_mds=is_mds),
        render_add_administrator_command(
            username, permissions_profile=permissions_profile, is_mds=is_mds
        ),
        render_add_api_key_command(username),
        *render_publish_logout_commands(),
    ]


# Candidate JSON field names for the generated key in `add api-key`'s response —
# the exact spelling isn't verifiable without live gear (NOT YET CONFIRMED).
# Checked case-insensitively, in this priority order.
_API_KEY_FIELD_CANDIDATES = ("api-key", "apiKey", "api_key", "value", "key")


def parse_api_key_from_add_api_key_output(stdout: str) -> str:
    """Extract the generated key from ``add api-key --format json``'s stdout.

    Raises ``ProvisioningError`` on any parse failure. The message is
    deliberately generic — never includes the raw ``stdout`` — because it may
    contain the secret and this exception can end up recorded on a job's
    (persisted) error field.
    """
    try:
        parsed = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        raise ProvisioningError(
            "could not parse API key: `add api-key` did not return valid JSON"
        ) from None
    if not isinstance(parsed, dict):
        raise ProvisioningError("could not parse API key: unexpected JSON shape")
    lowered = {str(k).lower(): v for k, v in parsed.items()}
    for candidate in _API_KEY_FIELD_CANDIDATES:
        value = lowered.get(candidate.lower())
        if isinstance(value, str) and value:
            return value
    raise ProvisioningError(
        "could not parse API key: no recognized field in `add api-key` JSON output"
    )


MGMT_API_NOTES = [
    NOTE_EMPHASIS + "Connect to Primary runs these automatically over SSH and captures "
    "the generated API key for you — this preview is shown so you can review the exact "
    "commands before they run. `add administrator` is skipped automatically if the "
    "account already exists (e.g. on a re-run to issue a fresh key).",
]

MDS_API_NOTE = (
    "This environment is Multi-Domain: the administrator is granted the "
    '`multi-domain-profile "Multi-Domain Super User"` (a global, all-Domains '
    "profile), not the single-domain `permissions-profile` used on an SMS."
)
