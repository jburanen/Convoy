---
name: firewall-discovery-domain-picker
description: Discover-firewalls has no source-server picker (one primary per environment, resolved automatically); on MDS it needs an operator-picked Domain, enumerated via show-domains logged in with no domain field
metadata:
  type: project
---

Two invariants the operator stated (2026-07-23) reshaped the "Discover firewalls"
modal (CPUSE tab), distinct from the older "Discover servers" modal (Provisioning
tab), which still has its own primary picker and was intentionally left alone:

- **One primary per environment.** An environment never has more than one Primary
  SMS or Primary MDS, so `HostConnector.primary_mgmt_host()`
  (`services/common.py`) resolves it automatically — `DiscoveryService.discover_firewalls`
  no longer takes a `primary_host_name` argument, and the modal has no "Discover
  from" `<select>`. If it can't find exactly one, `primary_mgmt_host()` raises
  `InventoryError`; if there happen to be two (shouldn't per the invariant), it
  silently picks the first rather than hard-erroring the UI.
- **MDS needs a Domain.** Gateways live inside a specific Domain/CMA, not the
  Global domain (Global is where shared servers like SmartEvent live — see
  [[mds-discovery-command]]). `DiscoveryService.list_domains()` enumerates them via
  the Management API `show-domains` command and the UI presents them in a
  `<select>` (`#discover-firewalls-domain`, shown only when
  `envIsMds[currentEnv]`); `discover_firewalls(env, domain=...)` then logs into
  that specific Domain (same `domain` login-payload field used for `"Global"`)
  before calling `show-gateways-and-servers`. No domain selected → a warning,
  zero servers, no API call.

**`show-domains` login context — NOT verified against live gear, only against
docs-tool guidance:** per the documentation tool, `show-domains` must be called
from a session logged in with **no** `domain` field at all (the MDS system
context), not `"Global"` and not any named domain — `ManagementAPIClient(...,
domain=None)` already omits it. Given this project's track record on MDS/API
specifics (see [[mds-discovery-command]] — six rounds to get one SSH command
right, twice from confidently wrong assumptions), treat this as unconfirmed until
someone runs it against a real MDS. If domain enumeration comes back empty or
errors on real gear, check this login-context assumption first before touching
anything else.

**How to apply:** don't reintroduce a source-server picker in this modal — resolve
the primary server-side. Any *new* per-Domain Management API call (not just
gateway discovery) should reuse `list_domains()`'s login pattern (no `domain`
field) to enumerate domains, then a second per-domain login to act within one.
