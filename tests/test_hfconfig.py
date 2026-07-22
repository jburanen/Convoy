from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Literal

import pytest

from chkp_cpuse_orch.hfconfig import HfConfig, extract_hf_config, parse_hf_config

HF_CONFIG_TEXT = """2474
PATCH_REG_PRODUCT=CPUpdates
PATCH_REG_VER=6.0
PATCH_REG_SP=5
PATCH_REG_MSP=6
PATCH_NAME=BUNDLE_R82_10_JUMBO_HF_MAIN
TAKE_NUMBER=24
BRANCH_NAME=R82_10_jumbo_hf_main
PACKAGE_TYPE=BUNDLE
ARCH=x86_64
CATEGORY=JUMBO
DIRECT_BASE_VERSION=R82.10
"""


def test_parse_hf_config_reads_known_fields_and_ignores_the_rest() -> None:
    hf = parse_hf_config(HF_CONFIG_TEXT)
    assert hf == HfConfig(
        patch_name="BUNDLE_R82_10_JUMBO_HF_MAIN",
        take_number=24,
        branch_name="R82_10_jumbo_hf_main",
        package_type="BUNDLE",
        category="JUMBO",
        direct_base_version="R82.10",
    )


def test_parse_hf_config_tolerates_missing_fields() -> None:
    assert parse_hf_config("not a config file at all") == HfConfig()
    assert parse_hf_config("") == HfConfig()


def test_parse_hf_config_ignores_non_numeric_take_number() -> None:
    hf = parse_hf_config("TAKE_NUMBER=not-a-number\nDIRECT_BASE_VERSION=R82.10\n")
    assert hf.take_number is None
    assert hf.direct_base_version == "R82.10"


def _make_tar(members: dict[str, bytes], *, mode: Literal["w"] = "w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_extract_hf_config_finds_it_several_layers_deep(tmp_path: Path) -> None:
    innermost = _make_tar({"hf.config": HF_CONFIG_TEXT.encode()})
    middle = _make_tar({"product/metadata.tar": innermost, "product/payload.bin": b"x" * 1000})
    package_path = tmp_path / "Check_Point_R82_10_JUMBO_HF_MAIN_Bundle_T24_FULL.tgz"
    with tarfile.open(package_path, mode="w:gz") as tar:
        info = tarfile.TarInfo("bundle/middle.tar")
        info.size = len(middle)
        tar.addfile(info, io.BytesIO(middle))

    hf = extract_hf_config(package_path)
    assert hf is not None
    assert hf.direct_base_version == "R82.10"
    assert hf.take_number == 24


def test_extract_hf_config_finds_it_at_the_top_level(tmp_path: Path) -> None:
    package_path = tmp_path / "pkg.tar"
    package_path.write_bytes(_make_tar({"hf.config": HF_CONFIG_TEXT.encode()}))

    hf = extract_hf_config(package_path)
    assert hf is not None
    assert hf.take_number == 24


def test_extract_hf_config_returns_none_when_absent(tmp_path: Path) -> None:
    package_path = tmp_path / "pkg.tar"
    package_path.write_bytes(_make_tar({"readme.txt": b"nothing to see here"}))

    assert extract_hf_config(package_path) is None


def test_extract_hf_config_returns_none_for_a_non_archive(tmp_path: Path) -> None:
    package_path = tmp_path / "not-a-tarball.tgz"
    package_path.write_bytes(b"this is definitely not a tar file")

    assert extract_hf_config(package_path) is None


def test_extract_hf_config_gives_up_past_the_depth_limit(tmp_path: Path) -> None:
    # Six layers of nesting — one more than _MAX_DEPTH allows — so hf.config
    # is never reached and we fall back to filename matching instead of
    # hanging or erroring.
    payload = HF_CONFIG_TEXT.encode()
    archive = _make_tar({"hf.config": payload})
    for i in range(6):
        archive = _make_tar({f"layer{i}.tar": archive})
    package_path = tmp_path / "deeply_nested.tar"
    package_path.write_bytes(archive)

    assert extract_hf_config(package_path) is None


def test_extract_hf_config_skips_oversized_nested_members(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import chkp_cpuse_orch.hfconfig as hfconfig_module

    monkeypatch.setattr(hfconfig_module, "_MAX_NESTED_SIZE", 10)  # smaller than our nested tar
    inner = _make_tar({"hf.config": HF_CONFIG_TEXT.encode()})
    package_path = tmp_path / "pkg.tar"
    package_path.write_bytes(_make_tar({"metadata.tar": inner}))

    assert extract_hf_config(package_path) is None
