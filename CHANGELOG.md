# Changelog

Shipped changes and fixed bugs, newest first. Each entry is labelled with the
version it shipped as — the same `vX.Y.Z` that goes in `src/convoy/__init__.py`
and the commit subject, so an entry here, the running version shown in the UI
footer and `/health`, and the commit that produced it all name the same thing.

Known issues and planned work live under Roadmap / Punch List in
[README.md](README.md); a fix that closes an item there moves it into this file
in the same commit as the fix and the version bump.

## v0.79.6

Says which account it is logging in as. A credential set with no `ssh_username` authenticates as whatever stale value sits in the host's own `Host.ssh_user`, and the only evidence was a rejected login in the *device's* auth log naming an account the operator never chose - real report 2026-08-27, an SG1800 refusing `admin` while its assigned set named a different user. v0.79.3 made a username mandatory on new saves, but rows predating that rule still carry none, and nothing in the tool ever said which name it had resolved. `spark.testcred` now logs `connecting over SSH to <host> as '<user>' (credential set)` before connecting, or a warning naming the fallback and where it came from when the set is silent; every connection also logs the resolved username and its source to the server log, so this is answerable for any job. The resolution itself is unchanged and was verified end-to-end against the real factory: the credential set wins whenever it names anyone

## v0.79.5

`scripts/deploy.sh` now seeds `data/config.yaml` from `examples/config.example.yaml` when it is missing. `Config.load()` treats a missing `/data/config.yaml` as fatal, so a first deploy from a fresh checkout built and started a container that then died on boot - surfacing as an unexplained health-check timeout rather than as "you have no config". The seed only ever creates what is absent; an existing config.yaml is operator-edited state and is never overwritten, which is what makes it safe on every deploy. The `--reset` branch's own copy of that step is gone: it ran *before* `git pull`, so a reset restored the example as it stood before the pull, and reset deletes config.yaml anyway - so the seed picks it up like any other first deploy. One code path instead of two

## v0.79.4

Password fields in the credential-set modal (SSH password, expert password, API key) now carry an eye button inside the field, so a long secret can be checked while it is typed instead of pasted blind. Wired generically - the form is scanned for `input[type="password"]`, so a field added later gets one for free - with inline SVG icons, since the page loads no external assets. `type="button"` on the toggle matters: a bare `<button>` in a form defaults to submit, which would have saved the set on the first peek. The revealed state is never sticky either: `form.reset()` clears values but leaves the input's `type` alone, so a field revealed before saving would still be readable the next time the modal opened - it is put back to masked on both open and close. The eye is skipped in the tab order (it is still reachable by mouse, and carries `aria-pressed`/`aria-label`). Also carries the JS half of v0.79.3, which shares this file: the credential form now requires an SSH username alongside any SSH secret

## v0.79.3

Storage-enabled environments still showed the per-host "SSH user" field in Add/Edit Server and Add/Edit Firewall, and a Spark gateway kept logging in as `admin` even though its assigned credential set named a different account. Two causes. First, a CSS specificity bug: `.stacked label` (class + type) outranks the generic `.hidden` (class alone), so *every* label in a stacked form threw the class away regardless of source order - the JS had been toggling it correctly the whole time. The same bug ran the other way too, showing the Credential set picker on storage-disabled environments. `#cp-user-label` already carried a one-off fix for this; `.stacked label.hidden` now covers the class of bug rather than the next instance of it. Second, `ssh_username` was optional on a credential set, so a set carrying an SSH secret without one silently fell back to the host's own `Host.ssh_user` - a field the UI hides and stops maintaining the moment storage is enabled, so it holds whatever stale value was last there. That is the same drift `.claude/memory/ssh-username-source-of-truth.md` was written about, through the hole that fix left open: it made the set authoritative but left the set free to say nothing. A username is now required on any set carrying an SSH secret, on edit too, so an older set without one has to gain a username rather than carry the gap forward. Keying it off the set's contents rather than a host's role lands the rule exactly where it belongs: firewalls always use SSH sets and always require it, while an API-only environment's management sets carry only an API key and don't. Also fixes the transfer path, which checked the resolved username directly and raised instead of falling back - so a session that had connected perfectly well refused to transfer, while naming the account it was already logged in as

## v0.79.2

Punch List bookkeeping: drops the three items v0.79.0 and v0.79.1 closed - the modal-dismissal-on-drag bug, partial credential-set updates, and the optional API key on API-only environments - which arrived in the list while those fixes were already being written, so they were never removed when the work shipped

## v0.79.1

Click-dragging to select text in a modal's field and releasing the button outside the dialog closed the modal, discarding whatever had been typed - reported against the credential-set editor, but every modal in the app had the same shape. The backdrop check was `ev.target.id === "<modal>"` inside a click handler, which is true both when you click the backdrop and when you merely *release* on it after pressing inside: the browser reports such a click against the nearest common ancestor of press and release, which is the modal container itself. All 20 handlers now share one `onBackdropClick()` helper that requires the press to have landed on the backdrop too, clearing the flag on every click so a press inside can't leave it armed for a later one. Carries the UI half of v0.79.0 as well: the credential modal's SSH fields are no longer hidden on API-only environments, and its form-level checks mirror put_set's new content-based rules

## v0.79.0

Credential-set validation keyed off the environment's access mode rather than the set's own contents: an API-only environment *required* an API key, everything else *required* an SSH secret. That was wrong in both directions. `api_only` only ever governed management-plane hosts (`HostConnector._check_ssh_reachable` exempts firewalls, which such an environment still patches over SSH), yet the credential modal hid the SSH fields whenever the environment was API-only - leaving no way to store the very credentials its firewall jobs need. And an API-key-only set became un-editable the moment its environment was toggled off API-only, since every save then demanded an SSH secret the set was never meant to have. The `api_only` parameter is gone from `put_set`; a set now needs an SSH secret **or** an API key, and one carrying an SSH secret needs exactly one of password/key plus an expert password. An API-key-only set needs neither. The SSH fields stay on offer in every environment - only the hint text changes with the mode. Also fixes the one edit that was genuinely impossible: switching a set from an SSH password to a private key, where the merge kept the stored password, the new key arrived alongside it, and the not-both check rejected the pair with nothing the operator could type to resolve it. Supplying either SSH secret now displaces the other; omitting both still keeps whichever is stored

## v0.78.6

A Spark gateway whose user is configured `bashUser on` lands you directly in expert at login, with no clish prompt in between - but `enter_expert()` sent `expert` regardless, asking for a password the session doesn't need and leaving either a not-found error or a pointless nested shell behind in the device's own history. It now reads the greeting the device sends at login first, and returns without sending anything at all when that greeting is already an expert prompt. A device that greets with silence still gets `expert` sent, exactly as before - no greeting is not evidence of being elevated. `spark.testcred` says so plainly in the job log rather than reporting a plain pass, because a run that never escalated never exercised the credential set's expert password. The test fakes were modelling a device that prints no prompt at login, which no real device does; they now open with one, and carry an `already_expert` flag for the bashUser-on case

## v0.78.5

`spark.testcred` failed against a real SG1800 *after* proving exactly what it set out to prove - the job log read `SSH login succeeded` then `expert mode entered successfully`, and only then `TransportError: SSH channel closed while waiting for '[>#]\s*$'`. The failure was in teardown: `GaiaExpertSession.exit_expert()` sends `exit` and waits for the clish prompt to come back, but that device doesn't treat expert as a nested shell to pop out of - it answered `exit` / `logout` and hung up, which is not what a 2026-08-19 probe saw on a different live Spark, where `_LOGIN_PROMPT` matched cleanly - so this is device- or build-dependent behaviour, not a regex that was simply wrong everywhere. A closed channel now counts as a successful exit, since all three callers (`_do_test_credentials`, `_enable_bash_user`, `_disable_bash_user`) close the shell on the very next line, so the device closing it first is the same destination reached sooner. `TransportTimeoutError` is deliberately re-raised ahead of that: it subclasses `TransportError`, so a bare catch would have swallowed it too - and a channel that stays open without ever returning a prompt is a stuck session, not a finished one, and still fails the job

## v0.78.4

Switching tabs kept the page's scroll position, so going from a long tab to a short one (CPUSE to Jobs, say) landed you partway down the new tab - or past its end, staring at whitespace - instead of at the top of what you'd just opened. The panels swap in place and nothing ever touched `window.scrollY`. `selectTab` now resets the scroll on an actual tab change, reading the outgoing tab from the DOM rather than tracking it separately so the two can't drift; clicking the tab you're already on still leaves your position alone. The reset is instant rather than smooth - the content has already been swapped by then, so an animated scroll would only blur through a tab you never asked to look at - and it nudges the header's scroll state directly, because `scrollTo(0, 0)` fires no scroll event when you were already at the top and the fade strip would otherwise linger on an unscrolled tab

## v0.78.2

`cpuse.install` and `cpuse.uninstall` left the Jobs tab's Output column empty for the whole run, so the only way to see how far an install had got was to expand the row and read the log - despite CPUSE reporting its own progress (`Installing 45%`) on every poll, which was already being written to that log. Those jobs now set the same Output-column headline the SCP/upload reporters and Spark install already used: `verifying`, then `installing` while the install command itself is running (which can sit for a while before CPUSE reports anything), then CPUSE's own status line verbatim once percentages start arriving. Written only when the value actually changes, matching the existing log-on-change rule - a long install parked at one percentage would otherwise rewrite the same value every poll - and cleared however the job ends, so a stale `Installing 45%` can't outlive it

## v0.69.1

v0.69.0's `color-scheme: light dark` fix wasn't actually enough - `#env-picker`'s dropdown popup still rendered with a light background in dark mode. The real cause: Chromium bases the popup listbox's own colors on the select's own resolved `background-color`, and `transparent` (set in v0.68.0 to make the closed control look borderless) gave it nothing usable to theme from, so it fell back to a plain light popup regardless of `color-scheme`. Fixed by setting `background: var(--bg)` instead - identical to the surrounding header, so still invisible as a "box" - plus explicit `#env-picker option` colors as a second guard

## v0.69.0

Four fixes/improvements bundled together. `#env-picker`'s dropdown popup rendered with a light background (unreadable against the dark theme) after v0.68.0 made it borderless - Chromium infers native-control theming from an explicit `color-scheme`, and a transparent/borderless `<select>` gave it nothing to go on; added `color-scheme: light dark` to `:root` so it (and other native chrome) follows the OS preference like the rest of the page already does. Uploading a package on the Packages tab no longer requires a browser refresh before it shows up in the CPUSE/Firewalls panels' "Import a stored package" pickers - those pickers were only ever repopulated by their own panel's full reload, not by `loadPackages()`, so switching tabs alone (which doesn't re-fetch anything) left them stale; a shared `populatePackageSelect()` helper now keeps all of them (plus the CDT tab's own, already-synced picker) in sync from one place. Any job that uploads a file over SSH/SCP (`spark.scp`, CPUSE import, push-to-repo, CDT staging) now surfaces its live "upload progress: NN%" as the Jobs tab's Output-column headline (`ProgressReporter` now calls `ctx.set_status()` too, the same mechanism Spark install's "waiting for reboot"/"pinging" text already used) instead of only being visible by opening the row's raw log. And the Packages tab's own upload field now shows a live percentage too - it switched from `fetch()` to `XMLHttpRequest` (`xhr.upload.onprogress`) for just this one request, since `fetch()` has no upload-progress hook and the browser already knows the file's size upfront from the local `File` object

## v0.68.0

Three header/tab-bar polish items bundled together. The title and tagline now stack in their own column (`#header-titles`) next to a slightly bigger logo (40px -> 46px); `header.condensed` (the same scroll-triggered class from v0.67.0) fades the tagline out (`max-height`/`opacity`, not `display`, so it stays smoothly transitioned) and shrinks the logo back down, leaving just the title on one line once scrolled. The environment picker (`#env-picker`) no longer inherits the shared `input, select, button` box styling (border/background/padding) - it now reads as plain bold text next to the "Env:" label rather than a boxed form control. And a `header::after` gradient strip (28px, background color fading to transparent) now sits just below the pinned tab bar, visible only in the condensed state, so table content scrolling underneath eases out instead of butting flush against the tabs

## v0.67.0

Rebuilt the top header: the subtitle now reads "Patching orchestration for Check Point systems" (was "CPUSE and CDT patch orchestration for on-prem SMS and MDS deployments"), and the logo, "Convoy", subtitle, and signed-in-user/logout controls all sit on one line instead of the title/subtitle stacking separately from a right-column session block. That whole identity row now stays visible while scrolling instead of disappearing with the rest of `<header>` - `<header>` itself (not just `#tabs`) is the sticky element, wrapping both the identity row and the tab bar as one pinned unit, since its containing block is `<body>` (as tall as the whole page) rather than something short it could run out of room inside - the same reasoning that already justified making `#tabs` sticky on its own. `#status-chips`/`#cred-cache-note` deliberately moved outside the sticky header, in normal flow, so they still scroll away like any other contextual content. A new `updateHeaderCondensed()` shrinks the header's vertical padding and logo size a few pixels into any scroll (CSS-transitioned, nothing hides or reflows) so the pinned bar doesn't keep eating a full header's worth of whitespace for the rest of the page

## v0.66.2

`toggleTagInFirewallFilter` (added in v0.66.1) correctly toggled off a single-word tag but re-added a multi-word one instead of removing it - it pushed a multi-word tag onto the token array as ONE element holding an embedded space, which displayed correctly at first but broke the instant that value round-tripped through the input and got re-split on whitespace (the standard way `#fw-filter`'s value is always read back), since a plain `indexOf` could then never match a multi-word tag as a single token again. It now looks for the tag's own words as a contiguous run within the split token array both to add and to remove, so a multi-word tag toggles as one unit correctly regardless of what else is already in the filter

## v0.66.1

Two small Firewalls-table filter follow-ups from last version. The filter box now has an "×" clear button (shown only while it has text, at the input's right edge) instead of requiring a manual select-all-and-delete. And clicking a tag badge already present in the filter now removes it instead of doing nothing - `addTagToFirewallFilter` became `toggleTagInFirewallFilter`, since a click is now genuinely a toggle rather than an add-only action

## v0.66.0

Closes the "warn on a different major version" Spark punch-list item, plus two Firewalls-table filter improvements bundled in the same batch. Installing on a Spark gateway now compares the picked `.img`'s major version against the firewall's currently detected one (first two dot/underscore-separated numeric groups - `R80.10.00` and `R80.10.10` are the same major version, `R80.10.x` vs `R81.10.x` isn't) and, on a mismatch, shows a dedicated confirm modal naming both versions before falling through to the existing reboot confirmation - skipped (not blocked) when either version can't be parsed, e.g. a never-refreshed row or an unusually-named file. Also: each tag badge on the Firewalls table is now clickable (mouse or keyboard) to add it as a token to the filter box and re-apply the filter, narrowing further on each additional click; and the filter itself now matches against the whole detected-state line - version, JHF, CPUSE Agent build, cluster membership - not just name/address/role/credential-set/tags, so a typed or clicked word can hit build numbers too

## v0.65.1

The environment picker lived in `<header>`, which scrolls away, while the tab bar below it is pinned to the top of the viewport (`position: sticky`) - so on any page long enough to scroll, the picker disappeared exactly when you'd want to switch environments mid-task. Moved into the `#tabs` nav itself (pushed to the row's right edge via `margin-left: auto`), so it now stays visible alongside the pinned tabs. Label shortened from "Environment:" to "Env:", and a new `resizeEnvPicker()` (canvas-measured, no layout reflow) narrows the closed `<select>` to fit just the *selected* environment's name - a bare `<select>` otherwise sizes its closed box to the widest option in the whole list, not the current one; the opened dropdown's own item widths are untouched, that's native popup behavior independent of the closed control's width

## v0.65.0

Closes the "built-in help docs" punch-list item, plus a few small UI cleanups bundled in the same batch. Every panel's long-form descriptive paragraph is now a one-clause summary inline, with the full explanation moved behind a new "?" button (always the right-most button in the panel's header row) opening a shared help modal - all 9 panels' brief/full text now lives in one new content file, `web/static/js/panel-help.js`, so wording changes never need to touch `index.html` or `app.js`. Also removed the sliding descriptive-text bar that used to run under the tab row (and its now-dead `CHKP_CPUSE_SHOW_TAB_HINTS` env var/setting) - it duplicated the same information the new per-panel help modals now carry, permanently, for content only useful once. On the Firewalls table, tags now render before (not after) the cluster-membership text on their shared line, and that text drops the redundant word "cluster" (`Active member in <name>` instead of `Active cluster member in <name>`). The Manage Environments modal's API-only toggle label is now `API-only (ie: Smart-1 Cloud)`, naming the motivating use case

## v0.64.0

Added a third environment access mode alongside SMS/MDS: **API-only** management, for estates (e.g. Smart-1 Cloud, or any management server the operator only has a Management API key for) reachable exclusively via the Management API - no SSH/SCP at all. New `api_only` flag on the environment (orthogonal to `is_mds`, same DB-column/`HostConnector`-attribute/manage-modal-toggle pattern already used for MDS-kind and credential storage) is enforced in one place - `HostConnector`'s two SSH chokepoints (`require_credentials`/`connect`) refuse SSH to any management-plane host in such an environment, which transparently covers CPUSE-patching the management server itself, CDT, Connect to Primary, the API-accessibility repair job, and Upload to Mgmt's SCP step - firewalls are untouched, since patching them was never dependent on how the management server itself is reached. Credential sets for such an environment need only an API key (`CredentialStore.put_set`'s new `api_only` parameter skips the SSH-secret/expert-password requirement added in v0.60.0). The UI hides Bootstrap and Connect to Primary on the Provisioning tab, the CPUSE tab's whole Management Servers panel, and the Packages tab's Upload to Mgmt button, and simplifies the Add Server / Add Credential modals down to the fields that still apply. Firewall discovery, gateway SIC-credential bootstrap, and estate discovery's SMS path already ran entirely over the Management API with no SSH involved, so they work unmodified; MDS peer discovery's SSH step already degraded to a warning rather than a hard failure on a missing SSH credential, so an MDS + API-only combination (fully orthogonal - Multi-Domain-ness and access mode are independent) just loses that one piece of best-effort enumeration instead of breaking

## v0.63.0

Spark firmware transfer (`spark.scp`) never checked whether `/storage` actually had room for the image before copying it - unlike the CPUSE-local import path, which has checked `/var/log`/`/` since v0.23-ish. Added a pre-check (fails closed with `PreCheckError`, no override) requiring the image's own size plus 10% headroom - simpler than CPUSE's per-path multiplier scheme since Spark's transfer is a plain file copy with no separate extraction/bookkeeping filesystem to size for. Runs before `bashUser` is even enabled, so a shortfall never touches device state at all. `_free_bytes`/`_fmt_bytes` (the `df -Pk` reader and byte-formatter `PatchingService` already had) moved to `services/common.py` as `remote_free_bytes`/`format_bytes` so both patching paths share one implementation

## v0.62.0

Firewalls had no way to attach operator-defined labels (e.g. "prod", "east-region") - added a `tags` property (JSON list, new `firewalls.tags` column) alongside the existing notes-style fields, edited via a chip-list widget in the Add/Edit Firewall modal (type a tag and press Enter/Add, or pick one already used elsewhere in the environment from the datalist suggestions - free text either way, nothing enforced). Unlike cluster_name/mds_domain, tags are ordinary operator data like notes - every add or edit replaces the full list, never kind-gated to creation only. Displayed on the firewalls table's detected-state row in the same spot cluster membership already occupies, as small badges, and shown even before a firewall's first Refresh (cluster membership itself still needs one, since it's genuinely live-refreshed data - tags aren't). Also wired into last version's free-text table filter, so a tag is now one more thing a typed word can match

## v0.61.0

The Firewalls panel had no way to narrow a long table down to a specific host, subnet, role, or credential set - added a single free-text filter box spanning the table width, above the header row. Space-separated words are ANDed together (each one narrows further), matched case-insensitively against name/role/credential-set as substrings; a word shaped like a full IPv4 address or a CIDR block (e.g. `192.0.2.10` or `192.0.2.0/24`) is instead matched against the address column with real IP semantics - exact equality or subnet containment - rather than as a substring, since naive substring matching on an IP (e.g. "10" hitting any address with a "10" in any octet) would be actively misleading; a partially-typed address that isn't a complete valid IPv4 just falls through to substring matching like everything else. Client-side only (no API round trip), re-applied after every table refresh/add/edit and cleared on environment switch

## v0.60.0

Every non-Spark Gaia host (management servers, CPUSE-patched firewalls, CDT-driven gateways) was provisioned with `/bin/bash` as its service account's login shell - a standing root-equivalent SSH session on every connect, with no elevation step, the opposite of the clish-login-then-`expert`-as-needed posture Spark firewalls already used. Provisioning no longer sets a shell at all (Gaia's own default is clish); a new `GaiaSession` transport detects live per connection whether an account lands in clish or (for an operator's own pre-existing bash-shell account) bash, and only escalates to `expert` the first time a job actually needs a bash-native command (CDT, disk-space checks, sha1 verification, install-log capture, `mgmt_cli`, ...) - clish-only operations like a plain Refresh never elevate at all. File transfer (SFTP/SCP) needs a genuinely bash-shell session, which a clish login can't serve, so it's handled by briefly flipping the account's own shell to `/bin/bash`, reconnecting, transferring, and flipping it back - always, even on failure, since leaving the account on a standing bash shell would defeat the whole point. Every stored credential set now requires an expert-mode password (previously optional except for Spark's own opt-in flag), and a storage-disabled environment's job-time credential prompt now asks for one too, but only for operations that actually escalate

## v0.59.0

Spark install used to guess at its own outcome from whatever its SSH session happened to observe issuing `upgrade_revert_image.sh` - real-hardware testing showed that observation is unreliable in both directions (see v0.58.2/v0.58.3), so it no longer tries. It now leaves that session alone, waits for the device's scheduled reboot to close it, pings the firewall until it responds again, reconnects over SSH, and compares `fw ver`'s reported build number against the installed package's own filename before declaring success - a confirmed mismatch fails the job, and giving up at the ping/reconnect stage without ever finding out is a distinct "timed out, go check" outcome rather than a false failure. The Jobs tab's Output column also now shows live status text ("installing", "waiting for reboot", "pinging", etc.) while an install runs, instead of staying blank until it finishes

## v0.58.2

A Spark install could report "succeeded" against a firewall that was never actually reformatted with the new firmware - real hardware confirmed `upgrade_revert_image.sh`'s own `mount_pfrm_inactive_part()` checks the exit status of the `mount` command that runs *after* `mke2fs`, not `mke2fs`'s own status, so `mke2fs` refusing to format an already-mounted inactive partition (likely a stale mount left by an earlier, incomplete attempt) doesn't necessarily abort the script - it can silently extract the new image onto unformatted, stale storage. The install job now scans for `mke2fs`'s own refusal text and fails the job instead of reporting success, telling the operator to reboot the firewall to clear the stale mount first. Also corrected a misleading log message that framed the SSH session returning control as the job "giving up" before a reboot - the script itself returns control on success too, well before the reboot it schedules for ~1 minute later; removed a redundant `bashUser off` at the start of install (that's transfer's job, at the end of `spark.scp`, not install's to repeat)

## v0.58.1

The Install confirmation dialog for a Spark firewall could say "Skipping `installer verify` — installing directly" - `installFirewallPackage`'s confirm() text was built purely from the (now-hidden, but still present and defaulted) skip-verify checkbox with no regard for host role, and `installer verify` isn't a CPUSE concept Spark has at all (Gaia Embedded has no CPUSE agent). The line is now only added for non-Spark rows

## v0.58.1

Radio buttons (e.g. the Spark firewall credential-scenario modal) rendered as huge, badly-misaligned blobs instead of a normal-sized dot next to its label - the generic `input, select, button` rule (padding/border/background meant for text fields) was being applied to `type="radio"`/`type="checkbox"` inputs too, and a `.stacked input { width: 100% }` rule (same specificity, later in the stylesheet) stretched the box to the full form width on top of that. Checkboxes/radios now get their own reset (native size, no border/background/padding) that out-ranks both

## v0.58.0

The Firewalls panel's "Upload and import to selected" button, for a Spark (Gaia Embedded) `.img` package, also ran the upgrade - a single `spark.scp` job did the whole sequence (SCP the image to `/storage`, then immediately `upgrade_revert_image.sh ... upgrade safe`, rebooting the device) with no way to just stage the file. Split into two independent jobs: `spark.scp` now only transfers and stores the image (no confirmation needed, doesn't reboot anything), and a new `spark.install` job runs the actual upgrade, wired to the same row-level Install button/picker CPUSE-patched firewalls already use (`POST .../install` now dispatches on host role). A transferred image shows up in that picker via the same `installable` cache CPUSE populates from live device state, since Spark has no equivalent query - this tool's own record of what it staged instead; fixed a latent bug found along the way where Refresh silently wiped that list on every check

## v0.57.1

Spark (Gaia Embedded) firmware transfer failed with `TransportError: SFTP upload to <host>:<path> failed: Channel closed` - the transfer reused `Transport.put()` (Paramiko's SFTP subsystem, same call used by the Gaia CPUSE import path) on the unvalidated assumption Spark's SSH server exposed it once `bashUser on` was run, but real hardware confirmed it doesn't - `bashUser on`'s own banner only ever advertised "SCP access enabled", never SFTP. The transfer now goes over a new `SSHClient.put_scp()` (classic SCP protocol, spoken directly over `exec_command("scp -t ...")`); the Gaia CPUSE path is untouched and still uses SFTP

## v0.57.0

Firewalls panel Refresh on Spark (Gaia Embedded) rows ran CPUSE's `show installer status`/packages/cluster-state against a host that has no CPUSE agent to query, and either failed outright or showed a meaningless summary line - `detect()` now branches on host role: Spark runs a plain `fw ver` and truncates the banner down to just the version/build (`This is Check Point's 1550 Appliance R81.10.17 - Build 892` -> `1550 Appliance R81.10.17 - Build 892`), everything else keeps the existing CPUSE path; also fixed the status line's orange "needs attention" highlight wrapping the agent build number along with the parenthetical update-status text it's meant for

## v0.56.2

Installing/verifying/importing/uninstalling a CPUSE package whose display name contains a space (e.g. `R82.10 Jumbo Hotfix Accumulator Recommended Jumbo Take 40`, exactly what CPUSE itself reports on some Gaia versions) failed with `CPUSEError: suspicious package identifier` - the shell-safety check on package IDs before they hit a clish command line (`cpuse.py`'s `_check_id`) allowlisted only `[A-Za-z0-9._-]+`, which was never actually the safety boundary (the whole command is `shlex.quote()`-wrapped as one unit in expert mode, or sent straight to a clish-only session in clish mode - spaces reach clish safely either way) and just rejected legitimate real-world names. Now blocklists actual shell metacharacters (`;&|` backtick `$<>\"'` and newlines) instead

## v0.56.1

A firewall's or management server's SSH login could silently use the wrong username once a credential set was assigned - `SSHClient.connect()` always used the entity's own stored `ssh_user` field, never the assigned credential set's `ssh_username`, and the two only stayed in sync via one-time UI copies (Add/Edit submit, Discover import) that went stale the moment a credential set was edited, reassigned, or - the actual case that surfaced this - a Discover Firewalls import stamped every row with the primary's own username regardless of which credential set ended up assigned to it. Right password, wrong account, generic "Authentication failed". The SSH username now resolves live from the assigned credential set at connect time for every host-touching job; `ssh_user` still exists but only matters for storage-disabled environments, which have no credential set to source it from - see `.claude/memory/ssh-username-source-of-truth.md`

## v0.56.0

Added Spark (Gaia Embedded) firmware patching: a "Test Credentials" link on Spark rows proves SSH login and `expert`-mode escalation work before you rely on them, and the Firewalls panel's bulk package selector now enforces compatibility - picking a `.tgz`/`.tar` package only allows selecting Gaia firewalls and vice versa for `.img`, picking a firewall of one kind first locks the package picker and the remaining rows to match (Management Servers panel unchanged). The transfer job follows the documented sequence (SSH, expert, `bashUser on`, log out, SCP the image to `/storage`, verify, SSH back in, expert, `bashUser off`, `upgrade_revert_image.sh ... upgrade safe`) and can't confirm the upgrade actually completes since Spark has nothing like CPUSE's `show installer package` to poll - only that the command was issued, same "not yet validated against live hardware" posture as the rest of this project's CPUSE/CDT parsers, with the two riskiest guesses (whether SFTP works over Spark's SSH server, and the `expert` password-prompt's exact text) isolated behind narrow interfaces so a wrong guess is a contained fix, not a rewrite - see `.claude/memory/spark-firmware-patching.md`

## v0.55.1

Removing a firewall (or any other action that reloads the Firewalls/Management-Servers tables while a background poll lands at the same moment) could duplicate every row in the table until a manual page refresh - `loadFirewalls()`/`loadServers()` each cleared and rebuilt their table on every call with no guard against two overlapping calls racing each other; v0.35.1 fixed one specific instance of this (a redundant reload inside `pollJobs()` itself) but left every other caller vulnerable to the same race, so it kept resurfacing - both functions now bail out of a stale call instead of rendering on top of a newer one

## v0.51.0

Manual Patching (CPUSE) Firewalls panel now offers a "Bootstrap Credentials" text link next to Refresh, shown when a status check fails with an authentication error - pushes the firewall's assigned credential set onto the gateway via the Management API's `run-script` (CPRID-backed, no SSH access needed to recover), reusing the same clish commands as the Provisioning tab's bootstrap panel

## v0.49.5

Packages tab now extracts and displays compatible major version, Take number, category, arch, and a free-text compatibility/prerequisite note from the package file itself (`hf.config` + `conditions_set.json`) at upload time - also fixed a latent bug where BUNDLE-type packages' per-component `hf.config` files (missing Take/category) could be picked up instead of the authoritative bundle-level one

## v0.49.4

Package verify command was invoked with the identifier from `show installer packages all` instead of the display name from `show installer packages imported` - `installer verify`/`installer install` need the latter, and CPUSE doesn't always render the same identifier across the two scopes

## v0.49.4

Install button on the Direct Patching (CPUSE) tab failed to register the first click - a background poll could land between picking a package and clicking Install, silently resetting the row's selection and re-disabling the button (disabled buttons don't dispatch click at all)

## v0.49.3

Jobs tab Target column was blank for push_to_repo jobs (grouped with the other filename-only pkgs.* jobs) - now shows the management server being pushed to

## v0.49.2

If a package import or upload-to-repo job fails we attempt to remove the file from the temp storage and alert in the job log if this was successful

## v0.49.1

Added percentage display for package uploads

## v0.48.2

Connect to Primary now auto-selects the credential set flagged "default" (if any) in the Credential set picker, instead of leaving it on "none — assign later"

## v0.48.2

In storage-disabled environments, the SSH user field/label in Connect to Primary rendered inline (browser-default) instead of aligned with Name/Address/Role/SSH port above it - also fixes an ID-vs-class CSS specificity bug where the fix itself broke hiding that field in storage-enabled environments

## v0.48.1

The Connect to Primary API-access repair used a fabricated `set-api-settings accessibility "minimize"` mgmt_cli command - corrected to the real `set api-settings accepted-api-calls-from "All IP addresses that can be used for GUI clients"`, with the `--domain "System Data"` flag it also needs on a standalone SMS

## v0.48.1

The "heads up" API-accessibility warning under Connect to Primary rendered as plain muted text instead of orange - `hint warn` had no matching CSS rule; now uses the same prov-note-warn/-err/-ok convention as the rest of that panel

## v0.48.0

No error checking for lack of API access - Connect to Primary now proactively checks the API's accessibility over SSH right after provisioning it, and offers to repair a require-local restriction; a 403 during discovery also explains the likely cause

## v0.47.3

Multi-select management servers for import - only starts first server, doesn't queue second

## v0.46.0

Provide a way to clean up the temp file storage after a timed out or failed package import job

## v0.46.0

Make timeout and check intervals longer during package import process to account for slower imports, improve how they are displayed in job log

## v0.45.3

Upload package to management repo fails with path formatting error
