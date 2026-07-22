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
    CATEGORY=JUMBO
    DIRECT_BASE_VERSION=R82.10
"""

from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

_HF_CONFIG_NAME = "hf.config"
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
    )


def extract_hf_config(package_path: Path) -> HfConfig | None:
    """Search the package archive for hf.config, descending into nested
    tar/tgz members (it's typically a couple of layers deep). Returns None
    if it isn't found or the archive can't be read — callers should fall
    back to filename-based matching in that case, not treat this as fatal."""
    try:
        with package_path.open("rb") as fh:
            data = _find_hf_config(fh, depth=0)
    except (OSError, tarfile.TarError):
        return None
    return parse_hf_config(data.decode("utf-8", errors="replace")) if data is not None else None


def _find_hf_config(fileobj: io.IOBase, depth: int) -> bytes | None:
    if depth > _MAX_DEPTH:
        return None
    try:
        with tarfile.open(fileobj=fileobj, mode="r:*") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                basename = member.name.rsplit("/", 1)[-1]
                if basename == _HF_CONFIG_NAME:
                    extracted = tar.extractfile(member)
                    if extracted is not None:
                        return extracted.read()
                elif _looks_like_archive(basename) and member.size <= _MAX_NESTED_SIZE:
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    found = _find_hf_config(io.BytesIO(extracted.read()), depth + 1)
                    if found is not None:
                        return found
    except tarfile.TarError:
        return None
    return None


def _looks_like_archive(name: str) -> bool:
    lower = name.lower()
    return lower.endswith((".tar", ".tgz", ".tar.gz"))
