"""Render Gaia clish commands that provision this tool's service account.

The operator pastes the generated commands into clish on EACH management
server. The account keeps Gaia's own default login shell — clish — rather
than being switched to ``/bin/bash``: SSH lands the tool in clish, and it
escalates to ``expert`` only for the specific commands that actually need it
(CDT, disk checks, sha1 verification, ...), never standing root/bash access
on connect. See .claude/memory/gaia-shell-posture.md.

Gaia's SFTP/SCP subsystem needs a genuinely bash-shell session, which a
clish login can't serve — package transfer handles this itself by
temporarily flipping the account's own shell to ``/bin/bash`` for the
duration of the transfer only, then flipping it back (``GaiaSession`` in
transport/ssh.py), so nothing here needs to provision a standing bash shell
for that purpose either.

An account an operator supplies that already has ``/bin/bash`` as its login
shell (older provisioning, or a pre-existing admin account) still works
unchanged — detected live per connection, not configured here.

Gaia's ``expert`` password (``set expert-password``) is a single secret
configured on the device itself, not tied to any one OS account — whatever
value is actually set on a given box is what belongs in that box's stored
credential set (or a storage-disabled job's inline prompt), regardless of
which account logs in.

The password is embedded ONLY as a salted SHA-512 crypt hash (Gaia's
``set user ... password-hash``), so the rendered script is safe to display,
copy, and paste. Nothing here talks to a server and nothing is stored.
"""

from __future__ import annotations

import json
import re
import secrets
import shlex

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


# Stand-in shown instead of a real hash when rendering for display only.
REDACTED_HASH = "<password-hash computed when the bootstrap actually runs>"


def render_gaia_user_commands(
    username: str,
    password: str,
    *,
    uid: int = DEFAULT_UID,
    role: str = DEFAULT_ROLE,
    redact_hash: bool = False,
) -> list[str]:
    """Clish commands to create the service account on one management server.

    Leaves the shell at Gaia's own default — clish (``/etc/cli.sh``) — rather
    than setting ``/bin/bash``: the tool elevates to ``expert`` itself,
    on demand, and only ever touches bash directly for file transfer (which
    briefly toggles the shell itself and restores it — see
    .claude/memory/gaia-shell-posture.md). Rounds=5000 keeps the classic
    ``$6$salt$hash`` format (no ``rounds=`` directive) for maximum Gaia
    compatibility.

    ``redact_hash`` renders the command shape with the hash replaced by a
    placeholder, for the confirm-dialog preview. A sha512_crypt hash at 5000
    rounds is offline-crackable, and the preview is a plain GET, so returning a
    real one handed any authenticated user a crackable hash of every firewall's
    stored password without ever needing the credential store's master key. The
    push itself (render_bootstrap_script) computes the real hash, so nothing is
    lost by withholding it here.

    The round count deliberately stays at 5000: raising it makes passlib emit a
    ``rounds=`` directive in the hash string, and whether Gaia's ``set user
    password-hash`` accepts that form is unverified. Getting it wrong would
    write an unusable hash onto a production account, so it is not a change to
    make without live confirmation.
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
    password_hash = REDACTED_HASH if redact_hash else hasher.hash(password)
    return [
        f"add user {username} uid {uid} homedir /home/{username}",
        f"set user {username} password-hash {password_hash}",
        f"add rba user {username} roles {role}",
        f"set user {username} gid 100",
        "save config",
    ]


_SPARK_PERMISSIONS = frozenset(
    {"access-policy", "read-write", "readonly", "remote-access", "Super Admin", "networking"}
)
# Full admin: CPUSE installer verbs require it, same rationale as DEFAULT_ROLE above.
DEFAULT_SPARK_PERMISSION = "Super Admin"


def render_spark_admin_commands(
    username: str,
    password: str,
    *,
    permission: str = DEFAULT_SPARK_PERMISSION,
) -> list[str]:
    """Clish command to create the service account on a Quantum Spark (SMB)
    appliance — Gaia Embedded's clish has a completely different account
    model than full Gaia's (``render_gaia_user_commands`` above): one ``add
    administrator`` command, no separate uid/rba/shell steps. Reference: SMB
    R81.10.X CLI Reference, ``add-administrator``
    (https://sc1.checkpoint.com/documents/SMB_R81.10.X/CLI/EN/Content/Topics/add-administrator.htm).

    Same password-hash approach as ``render_gaia_user_commands`` (classic
    ``$6$salt$hash``, matching the SMB doc's own ``cryptpw -a sha512``
    recommendation) — the password never appears in plaintext in the
    rendered command, so it's safe to display/copy/paste.

    Display-only (operator-directed, 2026-08-18): unlike
    ``render_bootstrap_script`` (full Gaia), there is no Management-API
    ``run-script`` push for this — Spark's support for that isn't
    established, and full Gaia's clish commands aren't valid there anyway.
    The operator pastes this into the device's own clish shell.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(
            f"invalid username {username!r}: lowercase letters, digits, '_' and '-', "
            "starting with a letter or '_', max 32 chars"
        )
    if len(password) < _MIN_PASSWORD_LEN:
        raise ProvisioningError(f"password must be at least {_MIN_PASSWORD_LEN} characters")
    if permission not in _SPARK_PERMISSIONS:
        raise ProvisioningError(
            f"invalid permission {permission!r}: must be one of {sorted(_SPARK_PERMISSIONS)}"
        )

    # types-passlib leaves .using() untyped; the call shape is stable.
    hasher = sha512_crypt.using(rounds=5000)  # type: ignore[no-untyped-call]
    password_hash = hasher.hash(password)
    return [
        f"add administrator username {username} password-hash {password_hash} "
        f'permission "{permission}"'
    ]


def render_bootstrap_script(username: str, password: str) -> str:
    """The bash script body for reapplying this account's credentials on a
    gateway via the Management API's ``run-script`` (services/
    gateway_bootstrap.py) — the same clish commands ``render_gaia_user_commands``
    renders for the Provisioning tab's bootstrap panel, each wrapped
    ``clish -c "..."`` since ``run-script`` executes as bash, not clish —
    unrelated to the account's own login shell (see
    ``GaiaShell.EXPERT`` in transport/ssh.py for the equivalent idiom
    elsewhere in this tool)."""
    commands = render_gaia_user_commands(username, password)
    return "\n".join(f"clish -c {shlex.quote(cmd)}" for cmd in commands)


PROVISIONING_NOTES = [
    "The user keeps Gaia's default clish shell — this tool elevates to `expert` "
    "itself, only for the specific commands that need it, and never leaves a "
    "standing bash/expert session.",
    "Also store an expert-mode password for this box in its credential set — "
    "it's the device's own `expert` password (`set expert-password`), not tied "
    "to this account, and is required before any CDT, install, or file-transfer "
    "operation can run.",
    "The password appears only as a salted SHA-512 hash, never in plaintext.",
]


# The clish/RBA account above is a *Gaia OS* user (SSH/clish/WebUI). The Check Point
# Management API authenticates *Security Management administrators* — a separate
# account system in the management database — so it needs its own provisioning. The
# tool's estate auto-discovery uses the Management API, so an API-enabled admin (with
# an API key) is what makes discovery work.
# mgmt_cli's session id is a bearer credential for the life of the login, and it
# lands in a file on the MANAGED server. This used to be one fixed path,
# "/tmp/cpuse_orch_mgmt_api.sid", written with a plain `>` redirect: predictable
# (so pre-creatable as a symlink by any local user, redirecting root's write),
# world-readable under the default umask, shared by concurrent jobs on the same
# host, and removed only on the success path. Now: an unpredictable per-run name,
# created under `umask 077`, and removed in a `finally` whatever happens.
_API_SESSION_DIR = "/tmp"
_API_SESSION_PREFIX = "cpuse_orch_mgmt_api"


def new_api_session_file() -> str:
    """A fresh, unguessable path for one mgmt_cli login's session id."""
    return f"{_API_SESSION_DIR}/{_API_SESSION_PREFIX}.{secrets.token_hex(16)}.sid"


def render_remove_session_file_command(session_file: str) -> str:
    """Best-effort cleanup, safe to run whether or not the file exists. Callers
    MUST run this in a finally — a failed login/publish leaves a live session id
    on disk otherwise."""
    return f"rm -f {shlex.quote(session_file)}"


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


def render_mgmt_login_command(session_file: str, *, is_mds: bool = False) -> str:
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
    # umask 077 so the session id is not world-readable the moment it lands.
    return f"umask 077; mgmt_cli login -r true{domain_flag} > {shlex.quote(session_file)}"


def render_show_administrator_command(username: str, session_file: str) -> str:
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
    return (
        f"mgmt_cli -s {shlex.quote(session_file)} show administrator name {username} --format json"
    )


def render_add_administrator_command(
    username: str,
    session_file: str,
    *,
    permissions_profile: str | None = None,
    is_mds: bool = False,
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
        f"mgmt_cli -s {shlex.quote(session_file)} add administrator name {username} "
        f'authentication-method "api key" {profile_param} "{permissions_profile}"'
    )


def render_add_api_key_command(username: str, session_file: str) -> str:
    """Issue a (new) API key for ``username``, printed once in its JSON output
    (CLI reference: ``add-api-key`` v2.1) — see
    ``parse_api_key_from_add_api_key_output``. Safe to re-run for an
    already-provisioned admin: each call issues a fresh key, which is exactly
    the "regenerate" path this tool relies on.
    """
    if not _USERNAME_RE.fullmatch(username):
        raise ProvisioningError(f"invalid username {username!r}")
    return (
        f"mgmt_cli -s {shlex.quote(session_file)} add api-key admin-name {username} --format json"
    )


def render_set_api_settings_command(session_file: str, *, is_mds: bool = False) -> str:
    """Widen which IPs the Management API accepts calls from, run against the
    session opened by ``render_mgmt_login_command``. The parameter is
    ``accepted-api-calls-from`` — NOT ``accessibility``/``"minimize"``, which
    an earlier docs-tool lookup fabricated wholesale (operator-corrected
    2026-07-26 against the real CLI reference: set-api-settings v2.1).
    ``"All IP addresses that can be used for GUI clients"`` is the
    least-broad fix for a 403 caused by ``api status``'s own ``accessibility:
    require local`` reading (a different, Gaia-CLI-side status field — not
    the mgmt_cli parameter name).

    Needs the same ``--domain "System Data"`` flag as the login command on a
    standalone SMS (operator-confirmed 2026-07-26) — unlike ``add
    administrator``/``add api-key``, this command doesn't inherit the
    session's login-time domain context on its own.

    Used by services/api_access.py's SSH repair flow, triggered from a 403
    on estate discovery (services/discovery.py)."""
    domain_flag = "" if is_mds else ' --domain "System Data"'
    return (
        f"mgmt_cli -s {shlex.quote(session_file)} set api-settings accepted-api-calls-from "
        f'"All IP addresses that can be used for GUI clients"{domain_flag}'
    )


def render_publish_logout_commands(session_file: str) -> list[str]:
    """Publish the session's changes, log out, and remove the session file."""
    return [
        f"mgmt_cli -s {shlex.quote(session_file)} publish",
        f"mgmt_cli -s {shlex.quote(session_file)} logout",
        render_remove_session_file_command(session_file),
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
    # A preview only — an automated run generates its own fresh session path.
    session_file = new_api_session_file()
    return [
        render_mgmt_login_command(session_file, is_mds=is_mds),
        render_add_administrator_command(
            username, session_file, permissions_profile=permissions_profile, is_mds=is_mds
        ),
        render_add_api_key_command(username, session_file),
        *render_publish_logout_commands(session_file),
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
