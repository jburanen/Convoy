"""Encrypted-at-rest credential store.

Gaia auth is mixed (see .claude/memory/patching-web-design.md): an SSH private key
for transport plus admin/expert passwords for privileged CPUSE steps — so a host
may hold several credentials, one per kind.

Security model:
- Plaintext secrets exist only in memory (``pydantic.SecretStr``); the SQLite row
  holds Fernet ciphertext. The repo is public and /data is a bind mount, so
  nothing readable may land on disk.
- The Fernet key is derived (Argon2id) from a master passphrase supplied at startup
  via ``CHKP_CPUSE_MASTER_KEY`` (or ``..._FILE`` for docker secrets) and is never
  persisted. The Argon2id salt and a canary token live in the DB so a wrong
  passphrase fails fast and loudly instead of yielding garbage.
"""

from __future__ import annotations

import base64
import os
import secrets
import threading
from enum import StrEnum

from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, SecretStr

from .errors import CredentialError
from .store import CredentialSetRow, Store

MASTER_KEY_ENV = "CHKP_CPUSE_MASTER_KEY"
MASTER_KEY_FILE_ENV = "CHKP_CPUSE_MASTER_KEY_FILE"

_SALT_META_KEY = "credential_kdf_salt"
_CANARY_META_KEY = "credential_canary"
_CANARY_PLAINTEXT = b"chkp-cpuse-orch credential canary v1"
_MIN_PASSPHRASE_LEN = 8


class CredentialKind(StrEnum):
    SSH_PASSWORD = "ssh_password"  # Gaia admin password (clish login)
    SSH_PRIVATE_KEY = "ssh_private_key"  # key material itself, not a file path
    EXPERT_PASSWORD = "expert_password"  # Gaia `expert` escalation password
    API_KEY = "api_key"  # Management API / Gaia REST key


# The SSH secrets that carry a login username (expert/API are secret-only).
_SSH_KINDS = (CredentialKind.SSH_PASSWORD, CredentialKind.SSH_PRIVATE_KEY)


class Credential(BaseModel):
    """A decrypted credential. Exists in memory only — never log or persist.
    ``host`` is the server this credential was resolved for (informational)."""

    host: str
    kind: CredentialKind
    username: str | None = None
    secret: SecretStr  # SecretStr keeps it out of repr()/logs
    environment: str = "default"  # credential namespaces are per-environment

    def reveal(self) -> str:
        return self.secret.get_secret_value()


class CredentialSetInfo(BaseModel):
    """Listing/UI view of a named credential set — deliberately secret-free."""

    name: str
    environment: str = "default"
    ssh_username: str | None = None
    ssh_auth: str  # "password" | "key" | "none" — which SSH secret the set holds
    has_expert: bool = False
    has_api: bool = False
    is_default: bool = False  # the environment's default set (assigned to new servers)


def load_master_key(environ: os._Environ[str] | dict[str, str] | None = None) -> str:
    """Resolve the master passphrase: env var, or file path (docker secret)."""
    env = os.environ if environ is None else environ
    value = env.get(MASTER_KEY_ENV)
    if not value:
        file_path = env.get(MASTER_KEY_FILE_ENV)
        if file_path:
            try:
                with open(file_path, encoding="utf-8") as fh:
                    value = fh.read().strip()
            except OSError as exc:
                raise CredentialError(f"cannot read master key file {file_path!r}: {exc}") from exc
    if not value:
        raise CredentialError(
            f"no master key: set {MASTER_KEY_ENV} (or {MASTER_KEY_FILE_ENV} pointing at a "
            "docker secret). The key encrypts stored credentials and is never persisted."
        )
    if len(value) < _MIN_PASSPHRASE_LEN:
        raise CredentialError(f"master key must be at least {_MIN_PASSPHRASE_LEN} characters")
    return value


class CredentialStore:
    """Manage named credential sets; everything at rest is ciphertext. A set is a
    "login object" (SSH user + SSH password/key + optional expert/API secrets) that
    is assigned to servers elsewhere (see services/environments.py)."""

    def __init__(self, store: Store, master_key: str) -> None:
        self._store = store
        self._fernet = Fernet(_derive_key(master_key, self._salt()))
        self._check_canary()

    def _salt(self) -> bytes:
        salt_hex = self._store.get_meta(_SALT_META_KEY)
        if salt_hex is None:
            salt = secrets.token_bytes(16)
            self._store.set_meta(_SALT_META_KEY, salt.hex())
            return salt
        return bytes.fromhex(salt_hex)

    def _check_canary(self) -> None:
        """Fail fast on a wrong master key instead of at first credential use."""
        canary = self._store.get_meta(_CANARY_META_KEY)
        if canary is None:
            self._store.set_meta(
                _CANARY_META_KEY, self._fernet.encrypt(_CANARY_PLAINTEXT).decode("ascii")
            )
            return
        try:
            if self._fernet.decrypt(canary.encode("ascii")) != _CANARY_PLAINTEXT:
                raise InvalidToken
        except InvalidToken:
            raise CredentialError(
                "master key does not match this database — stored credentials were "
                "encrypted under a different key. Restore the original key, or delete "
                "the credentials and re-enter them under the new key."
            ) from None

    # -- credential-set CRUD --------------------------------------------------

    def put_set(
        self,
        environment: str,
        name: str,
        *,
        ssh_username: str | None = None,
        ssh_password: str | None = None,
        ssh_private_key: str | None = None,
        expert_password: str | None = None,
        api_key: str | None = None,
    ) -> CredentialSetInfo:
        """Create a named login set, or update an existing one by name.

        On an **update** (a set with this name already exists), any argument left
        as ``None`` keeps the set's current value — so an operator can add just the
        API key to a bootstrap entry without re-typing the SSH secret. The effective
        row must still carry exactly one SSH secret (password or private key). The
        set's id is preserved, so server assignments to it survive. Secrets are
        encrypted here and never leave this process in plaintext."""
        existing = self._store.get_credential_set_by_name(environment, name)

        def _keep(new_plain: str | None, current_ct: bytes | None) -> bytes | None:
            # Provided value → (re)encrypt; omitted (None) → keep current ciphertext.
            return self._enc(new_plain) if new_plain is not None else current_ct

        if existing is not None:
            ssh_username = existing.ssh_username if ssh_username is None else ssh_username
            ssh_password_ct = _keep(ssh_password, existing.ssh_password_ct)
            ssh_private_key_ct = _keep(ssh_private_key, existing.ssh_private_key_ct)
            expert_password_ct = _keep(expert_password, existing.expert_password_ct)
            api_key_ct = _keep(api_key, existing.api_key_ct)
        else:
            ssh_password_ct = self._enc(ssh_password)
            ssh_private_key_ct = self._enc(ssh_private_key)
            expert_password_ct = self._enc(expert_password)
            api_key_ct = self._enc(api_key)

        if ssh_password_ct is not None and ssh_private_key_ct is not None:
            raise CredentialError("provide an SSH password or a private key, not both")
        if ssh_password_ct is None and ssh_private_key_ct is None:
            raise CredentialError("a credential set needs an SSH password or private key")

        row = CredentialSetRow(
            environment=environment,
            name=name,
            ssh_username=ssh_username or None,
            ssh_password_ct=ssh_password_ct,
            ssh_private_key_ct=ssh_private_key_ct,
            expert_password_ct=expert_password_ct,
            api_key_ct=api_key_ct,
        )
        if existing is not None:
            row.id = existing.id  # preserve id so server assignments survive
        return self._info(self._store.upsert_credential_set(row))

    def list_sets(self, environment: str) -> list[CredentialSetInfo]:
        return [self._info(r) for r in self._store.list_credential_sets(environment)]

    def get_info(self, environment: str, name: str) -> CredentialSetInfo | None:
        """Secret-free lookup by name, or None if it doesn't exist — used to
        decide add vs edit before submitting a cred.add/cred.edit job."""
        row = self._store.get_credential_set_by_name(environment, name)
        return None if row is None else self._info(row)

    def set_name(self, set_id: str) -> str | None:
        """Name of a set by id (secret-free), or None if it no longer exists."""
        row = self._store.get_credential_set(set_id)
        return None if row is None else row.name

    def delete_set(self, environment: str, name: str) -> bool:
        return self._store.delete_credential_set(environment, name)

    def set_default(self, environment: str, name: str) -> bool:
        """Make ``name`` the environment's default set (clears any previous one).
        Returns False if the set doesn't exist."""
        return self._store.set_default_credential_set(environment, name)

    def default_set_name(self, environment: str) -> str | None:
        """Name of the environment's default credential set, or None if unset."""
        row = self._store.get_default_credential_set(environment)
        return None if row is None else row.name

    def get_set_bundle(self, set_id: str, server_name: str) -> CredentialBundle:
        """Decrypt a credential set into a per-kind bundle for one server. Raises
        if the set no longer exists (e.g. deleted after assignment)."""
        row = self._store.get_credential_set(set_id)
        if row is None:
            raise CredentialError(f"credential set {set_id!r} not found")
        bundle: CredentialBundle = {}
        self._add(bundle, CredentialKind.SSH_PASSWORD, row.ssh_password_ct, row, server_name)
        self._add(bundle, CredentialKind.SSH_PRIVATE_KEY, row.ssh_private_key_ct, row, server_name)
        self._add(bundle, CredentialKind.EXPERT_PASSWORD, row.expert_password_ct, row, server_name)
        self._add(bundle, CredentialKind.API_KEY, row.api_key_ct, row, server_name)
        return bundle

    # -- helpers --------------------------------------------------------------

    def _enc(self, secret: str | None) -> bytes | None:
        if not secret:
            return None
        return self._fernet.encrypt(secret.encode("utf-8"))

    def _dec(self, ciphertext: bytes) -> str:
        try:
            return self._fernet.decrypt(ciphertext).decode("utf-8")
        except InvalidToken:
            # _check_canary should make this unreachable; keep the message clear anyway.
            raise CredentialError("cannot decrypt credential — wrong master key?") from None

    def _add(
        self,
        bundle: CredentialBundle,
        kind: CredentialKind,
        ciphertext: bytes | None,
        row: CredentialSetRow,
        server_name: str,
    ) -> None:
        if ciphertext is None:
            return
        # Only the SSH secrets carry the set's username; expert/API are secret-only.
        username = row.ssh_username if kind in _SSH_KINDS else None
        bundle[kind] = Credential(
            host=server_name,
            kind=kind,
            username=username,
            secret=SecretStr(self._dec(ciphertext)),
            environment=row.environment,
        )

    @staticmethod
    def _info(row: CredentialSetRow) -> CredentialSetInfo:
        ssh_auth = (
            "password"
            if row.ssh_password_ct is not None
            else "key"
            if row.ssh_private_key_ct is not None
            else "none"
        )
        return CredentialSetInfo(
            name=row.name,
            environment=row.environment,
            ssh_username=row.ssh_username,
            ssh_auth=ssh_auth,
            has_expert=row.expert_password_ct is not None,
            has_api=row.api_key_ct is not None,
            is_default=row.is_default,
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Argon2id(passphrase) → urlsafe-b64 32-byte Fernet key.

    This only runs once per process startup (not per-request), so the cost
    parameters are set well above Argon2id's interactive-login defaults —
    OWASP's higher-security recommendation (64 MiB, 3 iterations, 4 lanes)."""
    raw = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,  # KiB (64 MiB)
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    return base64.urlsafe_b64encode(raw)


# -- ephemeral (in-memory-only) credentials for storage-disabled environments ------

CredentialBundle = dict[CredentialKind, Credential]


def ensure_ssh_credential(creds: CredentialBundle, host_name: str, environment: str) -> None:
    """Reject a credential bundle that can't open an SSH session. Used at request
    time for environments that don't store credentials."""
    if CredentialKind.SSH_PASSWORD not in creds and CredentialKind.SSH_PRIVATE_KEY not in creds:
        raise CredentialError(
            f"provide an SSH password or private key for {host_name!r} in environment "
            f"{environment!r} — this environment does not store credentials"
        )


class JobCredentialVault:
    """In-memory credentials for jobs in storage-disabled environments.

    Secrets are supplied when a job is submitted, kept here keyed by job id, and
    dropped the instant the job finishes (the JobRunner calls ``discard``). They
    are never written to disk — that is the whole point of a storage-disabled
    environment. Thread-safe: the web threadpool submits while the runner's
    worker threads read/discard.
    """

    def __init__(self) -> None:
        self._by_job: dict[str, CredentialBundle] = {}
        self._lock = threading.Lock()

    def put(self, job_id: str, creds: CredentialBundle) -> None:
        with self._lock:
            self._by_job[job_id] = creds

    def get(self, job_id: str) -> CredentialBundle | None:
        with self._lock:
            return self._by_job.get(job_id)

    def require(self, job_id: str) -> CredentialBundle:
        creds = self.get(job_id)
        if creds is None:
            raise CredentialError(
                f"no in-memory credentials for job {job_id!r} — this environment does not "
                "store credentials and none were supplied for this job"
            )
        return creds

    def discard(self, job_id: str) -> None:
        with self._lock:
            self._by_job.pop(job_id, None)
