"""Provisioning jobs: add/edit/delete of management servers and CPUSE-patched
firewalls — run through the shared job runner, like credential-set and
package actions (see .claude/memory/patching-web-design.md), for Jobs-tab
visibility and audit history.

Local DB writes with no SSH host involved, submitted directly via
``JobRunner.submit`` rather than ``services.common.submit_host_job`` — same
shape as CredentialJobService/PackageJobService. Servers and firewalls share
one set of job kinds (``prov.add``/``prov.edit``/``prov.delete`` — operator-
directed, 2026-07-23: no server/firewall split in the Kind column) rather than
one pair per entity; ``params["entity"]`` is the internal discriminator the
single handler pair uses to call the right manager, invisible on the Jobs tab.

Whether an add is really an add or an edit is decided the same way
CredentialJobService decides it: a cheap existence read *before* the kind is
picked, not inside the handler. Unlike credentials, none of these fields are
secret, so everything — including an explicit credential-set assignment made
in the same Add/Edit modal submit — rides in ``JobRecord.params``, no vault
needed. Folding that assignment into the same job (rather than the separate
``POST .../credential`` call the frontend used to fire right after) closes a
race: the assignment call could 404 if it landed before the add/edit job
itself had run. ``credential_set`` is therefore tri-state — omitted (leave
any existing/default-on-create assignment alone), explicit ``None`` (clear
it), or a set name — using the ``UNSET`` sentinel below to tell "omitted" from
"explicitly cleared" apart, since both are spelled ``None`` in Python.

Validation (bad role, name colliding with the other entity table, etc.)
happens inside ``EnvironmentManager``/``FirewallManager`` as before, which
means — operator-directed, 2026-07-23, "match credentials" — it now surfaces
as a **failed job**, not a synchronous 400/409, same tradeoff already made for
cred.*. Only environment existence and (for delete) target existence are
cheap enough to keep as an instant, pre-submit check (mirrors
CredentialJobService.submit_delete's "don't defer an obviously-doomed job").
"""

from __future__ import annotations

import asyncio
from typing import Final

from ..errors import InventoryError
from ..jobs import JobContext, JobRunner
from ..store import JobRecord, Store
from .environments import EnvironmentManager
from .firewalls import FirewallManager

JOB_ADD = "prov.add"
JOB_EDIT = "prov.edit"
JOB_DELETE = "prov.delete"


class _Unset:
    __slots__ = ()

    def __repr__(self) -> str:
        return "<unset>"


UNSET: Final = _Unset()


class ProvisioningJobService:
    """Wraps EnvironmentManager/FirewallManager server+firewall CRUD as jobs."""

    def __init__(
        self,
        *,
        store: Store,
        env_manager: EnvironmentManager,
        firewall_manager: FirewallManager,
        runner: JobRunner,
    ) -> None:
        self._store = store
        self._env_manager = env_manager
        self._firewall_manager = firewall_manager
        self.runner = runner
        runner.register(JOB_ADD, self._put_job)
        runner.register(JOB_EDIT, self._put_job)
        runner.register(JOB_DELETE, self._delete_job)

    # -- submit: management servers ----------------------------------------------

    def submit_put_server(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int,
        notes: str | None,
        credential_set: str | None | _Unset = UNSET,
        triggered_by: str | None = None,
    ) -> JobRecord:
        kind = JOB_ADD if self._store.get_env_host(environment, name) is None else JOB_EDIT
        return self.runner.submit(
            kind,
            target=name,
            environment=environment,
            params=_put_params("server", address, role, ssh_user, ssh_port, notes, credential_set),
            triggered_by=triggered_by,
        )

    def submit_delete_server(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._store.get_env_host(environment, name) is None:
            raise InventoryError(f"server {name!r} not found in environment {environment!r}")
        return self.runner.submit(
            JOB_DELETE,
            target=name,
            environment=environment,
            params={"entity": "server"},
            triggered_by=triggered_by,
        )

    # -- submit: firewalls --------------------------------------------------------

    def submit_put_firewall(
        self,
        environment: str,
        *,
        name: str,
        address: str,
        role: str,
        ssh_user: str,
        ssh_port: int,
        notes: str | None,
        credential_set: str | None | _Unset = UNSET,
        triggered_by: str | None = None,
    ) -> JobRecord:
        kind = JOB_ADD if self._store.get_firewall(environment, name) is None else JOB_EDIT
        return self.runner.submit(
            kind,
            target=name,
            environment=environment,
            params=_put_params(
                "firewall", address, role, ssh_user, ssh_port, notes, credential_set
            ),
            triggered_by=triggered_by,
        )

    def submit_delete_firewall(
        self, environment: str, name: str, *, triggered_by: str | None = None
    ) -> JobRecord:
        if self._store.get_firewall(environment, name) is None:
            raise InventoryError(f"firewall {name!r} not found in environment {environment!r}")
        return self.runner.submit(
            JOB_DELETE,
            target=name,
            environment=environment,
            params={"entity": "firewall"},
            triggered_by=triggered_by,
        )

    # -- handlers -----------------------------------------------------------------

    async def _put_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_put, ctx)

    def _do_put(self, ctx: JobContext) -> None:
        name = ctx.job.target
        assert name is not None
        p = ctx.job.params
        environment = ctx.job.environment
        credential_set = p.get("credential_set", UNSET)
        if p["entity"] == "server":
            self._env_manager.add_server(
                environment,
                name=name,
                address=p["address"],
                role=p["role"],
                ssh_user=p["ssh_user"],
                ssh_port=p["ssh_port"],
                notes=p.get("notes"),
            )
            if credential_set is not UNSET:
                self._env_manager.assign_credential(environment, name, credential_set)
            noun = "management server"
        else:
            self._firewall_manager.add_firewall(
                environment,
                name=name,
                address=p["address"],
                role=p["role"],
                ssh_user=p["ssh_user"],
                ssh_port=p["ssh_port"],
                notes=p.get("notes"),
            )
            if credential_set is not UNSET:
                self._firewall_manager.assign_credential(environment, name, credential_set)
            noun = "firewall"
        verb = "added" if ctx.job.kind == JOB_ADD else "updated"
        ctx.log(f"{verb} {noun} {name!r}")

    async def _delete_job(self, ctx: JobContext) -> None:
        await asyncio.to_thread(self._do_delete, ctx)

    def _do_delete(self, ctx: JobContext) -> None:
        name = ctx.job.target
        assert name is not None
        if ctx.job.params["entity"] == "server":
            self._env_manager.remove_server(ctx.job.environment, name)
            noun = "management server"
        else:
            self._firewall_manager.remove_firewall(ctx.job.environment, name)
            noun = "firewall"
        ctx.log(f"deleted {noun} {name!r}")


def _put_params(
    entity: str,
    address: str,
    role: str,
    ssh_user: str,
    ssh_port: int,
    notes: str | None,
    credential_set: str | None | _Unset,
) -> dict[str, object]:
    params: dict[str, object] = {
        "entity": entity,
        "address": address,
        "role": role,
        "ssh_user": ssh_user,
        "ssh_port": ssh_port,
        "notes": notes,
    }
    if credential_set is not UNSET:
        params["credential_set"] = credential_set
    return params


__all__ = ["JOB_ADD", "JOB_DELETE", "JOB_EDIT", "UNSET", "ProvisioningJobService"]
