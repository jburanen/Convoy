"""Typed exceptions for the orchestrator.

Keeping these distinct lets the CLI and orchestrator fail *closed* with clear,
actionable messages instead of leaking raw SSH/API tracebacks into audit logs.
"""

from __future__ import annotations


class OrchestratorError(Exception):
    """Base class for all chkp-cpuse-orch errors."""


class ConfigError(OrchestratorError):
    """Invalid or missing tool configuration."""


class InventoryError(OrchestratorError):
    """Invalid or missing inventory (sites, servers, gateways)."""


class TransportError(OrchestratorError):
    """SSH / REST transport failure reaching a target host."""


class CDTError(OrchestratorError):
    """The Central Deployment Tool reported a failure."""


class CPUSEError(OrchestratorError):
    """A CPUSE / Deployment Agent operation failed on a Gaia host."""


class StoreError(OrchestratorError):
    """Local persistence (SQLite on the data volume) failed or is inconsistent."""


class CredentialError(OrchestratorError):
    """Credential store failure: missing credential, bad master key, or bad input."""


class AuthError(OrchestratorError):
    """Web authentication failed: bad LDAP credentials, missing group membership,
    or a directory that could not be reached. The message is deliberately generic
    at the HTTP boundary — never leak which check failed to the client."""


class JobError(OrchestratorError):
    """A background job could not be submitted or managed."""


class PackageError(OrchestratorError):
    """Package store failure: bad upload, checksum mismatch, or missing file."""


class ProvisioningError(OrchestratorError):
    """Invalid input for generating Gaia user-provisioning commands."""


class PreCheckError(OrchestratorError):
    """A pre-deployment health check failed; the run must not proceed."""


class SafetyViolation(OrchestratorError):
    """An action would violate an operational safety constraint (e.g. patching

    both cluster members at once, or running outside the maintenance window).
    """
