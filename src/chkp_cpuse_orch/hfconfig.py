"""Parses ``hf.config`` out of a CPUSE package archive.

A package's identifier in `show installer packages imported` can differ
wildly from its uploaded filename — Check Point renders some package types
(Jumbo Hotfix Accumulators) as a human-readable string like "R82.10 Jumbo
Hotfix Accumulator Take 24" instead of the filename (operator-confirmed,
2026-07-22). ``hf.config``, buried a few tar/tgz layers inside the package
archive, carries the same version + Take-number facts CPUSE's own text
encodes, so ``services/patching.py`` can match on those instead of guessing
at CPUSE's exact wording. See .claude/memory/cdt-cpuse-domain.md.

Example ``hf.config`` (leading line is a byte count, not a field):
    2474
    PATCH_REG_PRODUCT=CPUpdates
    PATCH_NAME=BUNDLE_R82_10_JUMBO_HF_MAIN
    TAKE_NUMBER=24
    BRANCH_NAME=R82_10_jumbo_hf_main
    PACKAGE_TYPE=BUNDLE
    ARCH=x86_64
    CATEGORY=JUMBO
    DIRECT_BASE_VERSION=R82.10

A BUNDLE-type package's metadata archive also carries one ``hf.config`` per
*component* under ``crs/<component>/hf.config`` (missing TAKE_NUMBER/
CATEGORY — those are bundle-level facts) alongside the one authoritative
bundle-level ``hf.config`` at the archive's own root. ``_find_hf_config``
below prefers the root file (see its docstring). The root's sibling
``conditions_set.json`` (same archive) carries a human-readable compatibility
statement in its ``set_description`` field, e.g. "This hotfix is supported
only for R82.10 (jess_main)." — surfaced to the Packages tab via
``extract_package_metadata``/``PackageMetadata.compatibility_note``.
"""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass
from pathlib import Path

_HF_CONFIG_NAME = "hf.config"
_CONDITIONS_SET_NAME = "conditions_set.json"
_MAX_DEPTH = 5  # nested tar/tgz layers to descend before giving up
# Skip nested archives bigger than this when descending — hf.config lives in
# a small metadata sub-archive, not the (possibly GB-scale) payload.
_MAX_NESTED_SIZE = 200 * 1024 * 1024


@dataclass(frozen=True)
class HfConfig:
    """The handful of hf.config fields relevant to identifying an imported
    package. Extra keys present in the real file are ignored."""

    patch_name: str | None = None
    take_number: int | None = None
    branch_name: str | None = None
    package_type: str | None = None
    category: str | None = None
    direct_base_version: str | None = None
    arch: str | None = None


@dataclass(frozen=True)
class PackageMetadata:
    """What ``extract_package_metadata`` pulls out of a package file for
    display on the Packages tab: the bundle-level ``hf.config`` plus a
    human-readable compatibility note, when present."""

    hf_config: HfConfig | None = None
    compatibility_note: str | None = None


def parse_hf_config(text: str) -> HfConfig:
    """Parse ``KEY=VALUE`` lines. The leading byte-count line, and any other
    non-matching lines, are ignored rather than treated as an error — this
    file's exact shape isn't documented, so tolerance beats a hard parse."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip()
    take = fields.get("TAKE_NUMBER")
    return HfConfig(
        patch_name=fields.get("PATCH_NAME"),
        take_number=int(take) if take is not None and take.isdigit() else None,
        branch_name=fields.get("BRANCH_NAME"),
        package_type=fields.get("PACKAGE_TYPE"),
        category=fields.get("CATEGORY"),
        direct_base_version=fields.get("DIRECT_BASE_VERSION"),
        arch=fields.get("ARCH"),
    )


def extract_hf_config(package_path: Path) -> HfConfig | None:
    """Search the package archive for hf.config, descending into nested
    tar/tgz members (it's typically a couple of layers deep). Returns None
    if it isn't found or the archive can't be read — callers should fall
    back to filename-based matching in that case, not treat this as fatal."""
    return extract_package_metadata(package_path).hf_config


def extract_package_metadata(package_path: Path) -> PackageMetadata:
    """Like ``extract_hf_config``, but also pulls the human-readable
    compatibility note out of ``conditions_set.json`` when the archive that
    holds the winning ``hf.config`` has one alongside it (real packages keep
    the two as siblings — see the module docstring). Same tolerant contract:
    any read/parse failure anywhere yields an empty ``PackageMetadata()``,
    never raises."""
    try:
        with package_path.open("rb") as fh:
            found = _find_metadata(fh, depth=0)
    except (OSError, tarfile.TarError):
        return PackageMetadata()
    if found is None:
        return PackageMetadata()
    hf_bytes, note_bytes = found
    hf_config = parse_hf_config(hf_bytes.decode("utf-8", errors="replace"))
    note = _parse_compatibility_note(note_bytes) if note_bytes is not None else None
    return PackageMetadata(hf_config=hf_config, compatibility_note=note)


def _parse_compatibility_note(data: bytes) -> str | None:
    try:
        parsed = json.loads(data.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    description = parsed.get("set_description")
    if not isinstance(description, str):
        return None
    description = description.strip()
    return description or None


def _find_metadata(fileobj: io.IOBase, depth: int) -> tuple[bytes, bytes | None] | None:
    """Depth-first search for the archive-root ``hf.config`` — preferring a
    root-level file (``member.name`` with no directory component) over one
    nested under ``crs/<component>/``. BUNDLE-type packages ship both: one
    per-component ``hf.config`` (missing TAKE_NUMBER/CATEGORY) for each of
    several components, plus one authoritative bundle-level file at the
    metadata archive's own root — and tar iteration lists the per-component
    ones first. Returning the first ``hf.config`` found (as this used to do)
    silently picked a per-component file instead of the authoritative one
    (operator-confirmed against a real R82.10 package, 2026-07-31). Returns
    the root file's bytes plus its sibling ``conditions_set.json``'s bytes
    (same archive), if present; falls back to any ``hf.config`` found
    (root or not, in this archive or a nested one) when no root-level file
    turns up anywhere reachable, preserving prior best-effort behavior."""
    if depth > _MAX_DEPTH:
        return None
    fallback: bytes | None = None
    try:
        with tarfile.open(fileobj=fileobj, mode="r:*") as tar:
            members = tar.getmembers()
            root_hf = next(
                (m for m in members if m.isfile() and m.name == _HF_CONFIG_NAME), None
            )
            if root_hf is not None:
                extracted = tar.extractfile(root_hf)
                if extracted is not None:
                    note_member = next(
                        (m for m in members if m.isfile() and m.name == _CONDITIONS_SET_NAME),
                        None,
                    )
                    note_bytes = None
                    if note_member is not None:
                        note_extracted = tar.extractfile(note_member)
                        note_bytes = note_extracted.read() if note_extracted is not None else None
                    return extracted.read(), note_bytes
            for member in members:
                if not member.isfile():
                    continue
                basename = member.name.rsplit("/", 1)[-1]
                if basename == _HF_CONFIG_NAME and fallback is None:
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        fallback = extracted.read()
                elif _looks_like_archive(basename) and member.size <= _MAX_NESTED_SIZE:
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    found = _find_metadata(io.BytesIO(extracted.read()), depth + 1)
                    if found is not None:
                        return found
    except tarfile.TarError:
        return (fallback, None) if fallback is not None else None
    return (fallback, None) if fallback is not None else None


def _looks_like_archive(name: str) -> bool:
    lower = name.lower()
    return lower.endswith((".tar", ".tgz", ".tar.gz"))
