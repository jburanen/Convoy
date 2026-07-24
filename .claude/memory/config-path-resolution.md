---
name: config-path-resolution
description: Relative paths in config.yaml anchor to the config file's own directory, not the process CWD
metadata:
  type: project
---

`Config.load()` (config.py) anchors every relative `paths.*` field and
`environments[].inventory` entry to the loaded config file's own directory
(`_anchor_relative_paths`), not the process's current working directory.
Absolute paths are left untouched.

**Why:** a fresh Docker deploy (2026-07-24, a new test server) crashed on
startup with `PermissionError: [Errno 13] Permission denied: 'state'` —
`examples/config.example.yaml`'s relative paths (`state_dir: state`, etc.)
resolved against the container's `WORKDIR` (`/app`, root-owned) instead of the
bind-mounted `/data` the operator actually intended, since the container runs
as a non-root user (`1001:1001`, see docker-compose.yml). The README used to
tell the operator to manually edit `/data/config.yaml` to swap in absolute
`/data/...` paths — an easy step to skip on a fresh setup, and exactly what
was skipped here.

**How to apply:** don't reintroduce CWD-relative resolution for config-driven
paths. When adding a new `Path` field to `config.Paths` or a similar
file-reference field, route it through `_anchor_relative_paths` (or the same
anchoring pattern) so a relative value in `config.yaml` always means "relative
to wherever that file lives," matching how the Docker bind mount is intended
to work with zero manual path edits. The no-config-file path (bare defaults,
`Config.load()` with nothing set) is unaffected — those still resolve
relative to the CWD, since there's no config file directory to anchor to.
