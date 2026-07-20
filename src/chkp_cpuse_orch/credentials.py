"""Encrypted-at-rest credential store.

Gaia auth is mixed (see .claude/memory/patching-web-design.md): an SSH private key
for transport plus admin/expert passwords for privileged CPUSE steps — so a host
may hold several credentials, one per kind.

Security model:
- Plaintext secrets exist only in memory (``pydantic.SecretStr``); the SQLite row
  holds Fernet ciphertext. The repo is public and /data is a bind mount, so
  nothing readable may land on disk.
- The Fernet key is derived (scrypt) from a master passphrase supplied at startup
  via ``CHKP_CPUSE_MASTER_KEY`` (or ``..._FILE`` for docker secrets) and is never
  persisted. The scrypt salt and a canary token live in the DB so a wrong
  passphrase fails fast and loudly instead of yielding garbage.
"""

from __future__ import annotations

import base64
import os
import secrets
import threading
from enum import StrEnum

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pydantic import BaseModel, SecretStr

from .errors import CredentialError
from .store import CredentialRecord, Store

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


class Credential(BaseModel):
    """A decrypted credential. Exists in memory only — never log or persist."""

    host: str  # inventory Host.name, or "*" for an environment-wide default
    kind: CredentialKind
    username: str | None = None
    secret: SecretStr  # SecretStr keeps it out of repr()/logs
    environment: str = "default"  # credential namespaces are per-environment

    def reveal(self) -> str:
        return self.secret.get_secret_value()


class CredentialInfo(BaseModel):
    """Listing/UI view of a stored credential — deliberately secret-free."""

    host: str
    kind: CredentialKind
    username: str | None
    environment: str = "default"


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
    """Put/get credentials for hosts; everything at rest is ciphertext."""

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

    # -- CRUD -----------------------------------------------------------------

    def put(self, cred: Credential) -> CredentialInfo:
        if not cred.reveal():
            raise CredentialError("refusing to store an empty secret")
        rec = CredentialRecord(
            environment=cred.environment,
            host=cred.host,
            kind=cred.kind.value,
            username=cred.username,
            ciphertext=self._fernet.encrypt(cred.reveal().encode("utf-8")),
        )
        stored = self._store.upsert_credential(rec)
        return CredentialInfo(
            host=stored.host,
            kind=CredentialKind(stored.kind),
            username=stored.username,
            environment=stored.environment,
        )

    def get(self, host: str, kind: CredentialKind, environment: str = "default") -> Credential:
        cred = self.try_get(host, kind, environment)
        if cred is None:
            raise CredentialError(
                f"no {kind.value} credential stored for host {host!r} "
                f"in environment {environment!r}"
            )
        return cred

    def try_get(
        self, host: str, kind: CredentialKind, environment: str = "default"
    ) -> Credential | None:
        rec = self._store.get_credential(host, kind.value, environment=environment)
        if rec is None:
            return None
        return self._decrypt(rec)

    def for_host(self, host: str, environment: str = "default") -> dict[CredentialKind, Credential]:
        """All credentials for one host in one environment, keyed by kind."""
        return {
            CredentialKind(rec.kind): self._decrypt(rec)
            for rec in self._store.list_credentials(host, environment=environment)
        }

    def list(self, environment: str | None = None) -> list[CredentialInfo]:
        return [
            CredentialInfo(
                host=r.host,
                kind=CredentialKind(r.kind),
                username=r.username,
                environment=r.environment,
            )
            for r in self._store.list_credentials(environment=environment)
        ]

    def delete(self, host: str, kind: CredentialKind, environment: str = "default") -> bool:
        return self._store.delete_credential(host, kind.value, environment=environment)

    def _decrypt(self, rec: CredentialRecord) -> Credential:
        try:
            plaintext = self._fernet.decrypt(rec.ciphertext).decode("utf-8")
        except InvalidToken:
            # _check_canary should make this unreachable; keep the message clear anyway.
            raise CredentialError(
                f"cannot decrypt {rec.kind} credential for {rec.host!r} — wrong master key?"
            ) from None
        return Credential(
            host=rec.host,
            kind=CredentialKind(rec.kind),
            username=rec.username,
            secret=SecretStr(plaintext),
            environment=rec.environment,
        )


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """scrypt(passphrase) → urlsafe-b64 32-byte Fernet key. Interactive-grade cost."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


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
