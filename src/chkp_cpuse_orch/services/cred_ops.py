"""Credential-set jobs: add/edit/delete — run through the shared job runner,
like CPUSE/CDT/pkgs jobs, for Jobs-tab visibility and audit history (see
.claude/memory/patching-web-design.md). Local encrypt+DB writes with no SSH
host involved, submitted directly via ``JobRunner.submit`` rather than
``services.common.submit_host_job`` — same shape as PackageJobService.

The plaintext secrets themselves must never reach ``JobRecord.params`` (it's
persisted as plain JSON in the jobs table — see store.py — and later archived
to a flat file), which would defeat the whole point of encrypting credentials
at rest. Instead they ride in the same in-memory-only ``JobCredentialVault``
already used for storage-disabled environments' one-shot credentials: put
there under the job id *before* submission, read back by the handler, and
dropped the instant the job finishes (``JobRunner``'s ``on_job_finished``
hook, already wired to ``vault.discard``) — the vault doesn't care why the
credentials are needed, only that they're job-scoped and ephemeral.
"""

from __future__ import annotations

import asyncio

from pydantic import SecretStr

from ..credentials import (
    Credential,
    CredentialBundle,
    CredentialKind,
    CredentialStore,
    JobCredentialVault,
)
from ..errors import InventoryError
from ..jobs import JobContext, JobRunner
from ..store import JobRecord, new_id

JOB_ADD = "cred.add"
JOB_EDIT = "cred.edit"
JOB_DELETE = "cred.delete"


class CredentialJobService:
    """Wraps CredentialStore's write operations as background jobs."""

    def __init__(
        self, *, credentials: CredentialStore, runner: JobRunner, vault: JobCredentialVault
    ) -> None:
        self._credentials = credentials
        self._vault = vault
        self.runner = runner
        runner.register(JOB_ADD, self._put_job)
        runner.register(JOB_EDIT, self._put_job)
        runner.register(JOB_DELETE, self._delete_job)

    # -- submit -------------------------------------------------------------

    def submit_put(
        self,
        environment: str,
        *,
        name: str,
        ssh_username: str | None,
        ssh_password: str | None,
        ssh_private_key: str | None,
        expert_password: str | None,
        api_key: str | None,
        default_if_none: bool,
        triggered_by: str | None = None,
    ) -> JobRecord:
        """``ssh_username``/``default_if_none`` aren't secret and travel in
        ``params``; the four secret fields go in the vault instead, keyed by
        job id. Whether this is an add or an edit is decided here (a
        secret-free read), before the kind is picked — the job kind itself is
        what the Jobs tab's Env/Target columns key off of."""
        kind = JOB_ADD if self._credentials.get_info(environment, name) is None else JOB_EDIT
        bundle: CredentialBundle = {}
        for value, ckind in (
            (ssh_password, CredentialKind.SSH_PASSWORD),
            (ssh_private_key, CredentialKind.SSH_PRIVATE_KEY),
            (expert_password, CredentialKind.EXPERT_PASSWORD),
            (api_key, CredentialKind.API_KEY),
        ):
            if value is not None:
                bundle[ckind] = Credential(
                    host=name,
                    kind=ckind,
                    username=ssh_username,
                    secret=SecretStr(value),
                    environment=environment,
                )

        job_id = new_id()
        self._vault.put(job_id, bundle)
        try:
            return self.runner.submit(
                kind,
                target=name,
                environment=environment,
                params={"ssh_username": ssh_username, "default_if_none": default_if_none},
                job_id=job_id,
                triggered_by=triggered_by,
            )
        except Exception:
            self._vault.discard(job_id)
            raise

    def submit_delete(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._credentials.get_info(environment, name) is None:
            raise InventoryError(
                f"credential set {name!r} not found in environment {environment!r}"
            )
        return self.runner.submit(
            JOB_DELETE, target=name, environment=environment, triggered_by=triggered_by
        )

    # -- handlers -------------------------------------------------------------

    async def _put_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_put, ctx)

    def _do_put(self, ctx: JobContext) -> None:
        bundle = self._vault.require(ctx.job.id)

        def _plain(kind: CredentialKind) -> str | None:
            cred = bundle.get(kind)
            return cred.reveal() if cred is not None else None

        name = ctx.job.target
        assert name is not None
        p = ctx.job.params
        info = self._credentials.put_set(
            ctx.job.environment,
            name,
            ssh_username=p.get("ssh_username"),
            ssh_password=_plain(CredentialKind.SSH_PASSWORD),
            ssh_private_key=_plain(CredentialKind.SSH_PRIVATE_KEY),
            expert_password=_plain(CredentialKind.EXPERT_PASSWORD),
            api_key=_plain(CredentialKind.API_KEY),
        )
        no_default_yet = self._credentials.default_set_name(ctx.job.environment) is None
        if p.get("default_if_none") and no_default_yet:
            self._credentials.set_default(ctx.job.environment, name)
        verb = "added" if ctx.job.kind == JOB_ADD else "updated"
        ctx.log(f"{verb} credential set {name!r} (ssh_auth={info.ssh_auth})")

    async def _delete_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_delete, ctx)

    def _do_delete(self, ctx: JobContext) -> None:
        name = ctx.job.target
        assert name is not None
        deleted = self._credentials.delete_set(ctx.job.environment, name)
        ctx.log(
            f"deleted credential set {name!r}" if deleted else "credential set was already gone"
        )


__all__ = ["JOB_ADD", "JOB_DELETE", "JOB_EDIT", "CredentialJobService"]
