from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pydantic import ValidationError

from reverserx.tools.base import ToolContext
from reverserx.tools.static.apk import (
    ApkInspectInput,
    ApkInspectionError,
    ApkInspectTool,
    ApkRole,
    PackageSourceKind,
    inspect_android_package,
)


def _apk_bytes(*, dex: bool = True, extra: dict[str, bytes] | None = None) -> bytes:
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest")
        if dex:
            archive.writestr("classes.dex", b"dex\n035\x00fixture")
        for name, value in (extra or {}).items():
            archive.writestr(name, value)
    return output.getvalue()


def _write_zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        for name, value in members:
            archive.writestr(name, value)


def test_inspects_standalone_apk_and_preserves_identity(tmp_path: Path) -> None:
    apk = tmp_path / "fixture.apk"
    content = _apk_bytes(extra={"classes2.dex": b"second", "assets/a.txt": b"a"})
    apk.write_bytes(content)

    result = inspect_android_package(apk)

    assert result.source_kind is PackageSourceKind.APK
    assert result.source_sha256 == hashlib.sha256(content).hexdigest()
    assert result.source_size_bytes == len(content)
    assert result.base_apk.name == "fixture.apk"
    assert result.base_apk.role is ApkRole.BASE
    assert result.base_apk.sha256 == result.source_sha256
    assert result.base_apk.dex_files == ("classes.dex", "classes2.dex")
    assert result.split_apks == ()
    assert result.all_apks == (result.base_apk,)


def test_tool_has_strict_input_and_returns_serializable_result(tmp_path: Path) -> None:
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(_apk_bytes())
    context = ToolContext(project_id="prj_fixture", data_dir=tmp_path)

    arguments = ApkInspectInput.model_validate({"path": str(apk)})
    result = ApkInspectTool().execute(context, arguments)

    assert result.output["source_kind"] == "apk"
    assert result.output["base_apk"]["name"] == "fixture.apk"
    with pytest.raises(ValidationError):
        ApkInspectInput.model_validate({"path": str(apk), "unknown": True})


def test_apkm_uses_info_metadata_and_sorts_splits(tmp_path: Path) -> None:
    bundle = tmp_path / "fixture.apkm"
    base = _apk_bytes()
    arm = _apk_bytes(dex=False)
    density = _apk_bytes(dex=False)
    info = {
        "package_name": "com.example.fixture",
        "split_apks": [
            {"file": "payload/main.apk", "id": "base"},
            {"file": "splits/z-density.apk", "id": "config.xxhdpi"},
            {"file": "splits/a-arm.apk", "id": "config.arm64_v8a"},
        ],
    }
    _write_zip(
        bundle,
        [
            ("splits/z-density.apk", density),
            ("info.json", json.dumps(info).encode()),
            ("payload/main.apk", base),
            ("splits/a-arm.apk", arm),
            ("icon.png", b"png"),
        ],
    )

    result = inspect_android_package(bundle)

    assert result.source_kind is PackageSourceKind.APKM_ARCHIVE
    assert result.info == info
    assert result.base_apk.name == "payload/main.apk"
    assert result.base_apk.sha256 == hashlib.sha256(base).hexdigest()
    assert result.base_apk.compressed_size_bytes is not None
    assert [item.name for item in result.split_apks] == [
        "splits/a-arm.apk",
        "splits/z-density.apk",
    ]
    assert [item.split_id for item in result.split_apks] == [
        "config.arm64_v8a",
        "config.xxhdpi",
    ]


def test_apkm_exact_base_name_wins_without_metadata(tmp_path: Path) -> None:
    bundle = tmp_path / "fixture.zip"
    _write_zip(
        bundle,
        [
            ("split_config.en.apk", _apk_bytes(dex=False)),
            ("base.apk", _apk_bytes()),
        ],
    )

    result = inspect_android_package(bundle)

    assert result.base_apk.name == "base.apk"
    assert result.split_apks[0].name == "split_config.en.apk"
    assert result.split_apks[0].split_id == "config.en"


def test_unpacked_apkm_has_stable_inventory_hash(tmp_path: Path) -> None:
    bundle = tmp_path / "unpacked"
    splits = bundle / "splits"
    splits.mkdir(parents=True)
    (bundle / "base.apk").write_bytes(_apk_bytes())
    (splits / "split_config.en.apk").write_bytes(_apk_bytes(dex=False))
    (bundle / "info.json").write_text('{"base_apk":"base.apk"}')

    first = inspect_android_package(bundle)
    second = inspect_android_package(bundle)

    assert first.source_kind is PackageSourceKind.APKM_DIRECTORY
    assert first.source_sha256 == second.source_sha256
    assert first.source_size_bytes == sum(
        path.stat().st_size for path in bundle.rglob("*") if path.is_file()
    )
    assert first.base_apk.name == "base.apk"
    assert first.split_apks[0].name == "splits/split_config.en.apk"


@pytest.mark.parametrize(
    "member_name",
    ["../outside.apk", "/absolute.apk", "folder\\evil.apk", "C:/evil.apk"],
)
def test_rejects_unsafe_outer_member_names(tmp_path: Path, member_name: str) -> None:
    bundle = tmp_path / "unsafe.apkm"
    _write_zip(bundle, [(member_name, _apk_bytes())])

    with pytest.raises(ApkInspectionError, match="unsafe ZIP member"):
        inspect_android_package(bundle)


def test_rejects_unsafe_nested_apk_member(tmp_path: Path) -> None:
    bundle = tmp_path / "unsafe.apkm"
    nested = io.BytesIO()
    with ZipFile(nested, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("../classes.dex", b"dex")
    _write_zip(bundle, [("base.apk", nested.getvalue())])

    with pytest.raises(ApkInspectionError, match="unsafe ZIP member"):
        inspect_android_package(bundle)


def test_rejects_duplicate_zip_members(tmp_path: Path) -> None:
    apk = tmp_path / "duplicate.apk"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _write_zip(
            apk,
            [
                ("AndroidManifest.xml", b"one"),
                ("AndroidManifest.xml", b"two"),
            ],
        )

    with pytest.raises(ApkInspectionError, match="duplicate ZIP member"):
        inspect_android_package(apk)


def test_rejects_suspicious_compression_ratio(tmp_path: Path) -> None:
    apk = tmp_path / "bomb.apk"
    _write_zip(
        apk,
        [
            ("AndroidManifest.xml", b"manifest"),
            ("assets/zeros.bin", b"\x00" * (2 * 1024 * 1024)),
        ],
    )

    with pytest.raises(ApkInspectionError, match="compression ratio"):
        inspect_android_package(apk)


@pytest.mark.parametrize("suffix", ["apk", "apkm"])
def test_rejects_malformed_archives(tmp_path: Path, suffix: str) -> None:
    package = tmp_path / f"malformed.{suffix}"
    package.write_bytes(b"not a ZIP")

    with pytest.raises(ApkInspectionError, match="malformed"):
        inspect_android_package(package)


def test_rejects_apk_without_manifest(tmp_path: Path) -> None:
    apk = tmp_path / "invalid.apk"
    _write_zip(apk, [("classes.dex", b"dex")])

    with pytest.raises(ApkInspectionError, match="AndroidManifest.xml"):
        inspect_android_package(apk)


def test_rejects_ambiguous_and_missing_base(tmp_path: Path) -> None:
    ambiguous = tmp_path / "ambiguous.apkm"
    _write_zip(
        ambiguous,
        [
            ("one.apk", _apk_bytes()),
            ("two.apk", _apk_bytes()),
        ],
    )
    missing = tmp_path / "missing.apkm"
    _write_zip(
        missing,
        [
            ("one/base.apk", _apk_bytes()),
            ("two/base.apk", _apk_bytes()),
        ],
    )

    with pytest.raises(ApkInspectionError, match="cannot determine"):
        inspect_android_package(ambiguous)
    with pytest.raises(ApkInspectionError, match="ambiguous base.apk"):
        inspect_android_package(missing)


def test_single_code_bearing_apk_is_deterministic_base(tmp_path: Path) -> None:
    bundle = tmp_path / "code.apkm"
    _write_zip(
        bundle,
        [
            ("resources-fr.apk", _apk_bytes(dex=False)),
            ("application.apk", _apk_bytes()),
        ],
    )

    result = inspect_android_package(bundle)

    assert result.base_apk.name == "application.apk"


@pytest.mark.parametrize(
    ("raw_info", "message"),
    [
        (b"not-json", "malformed info.json"),
        (b"[]", "JSON object"),
        (b'{"base_apk":"base.apk","base_apk":"other.apk"}', "duplicate"),
    ],
)
def test_rejects_invalid_info_json(
    tmp_path: Path, raw_info: bytes, message: str
) -> None:
    bundle = tmp_path / "invalid-info.apkm"
    _write_zip(bundle, [("base.apk", _apk_bytes()), ("info.json", raw_info)])

    with pytest.raises(ApkInspectionError, match=message):
        inspect_android_package(bundle)


def test_rejects_metadata_reference_to_missing_base(tmp_path: Path) -> None:
    bundle = tmp_path / "missing-metadata-base.apkm"
    _write_zip(
        bundle,
        [
            ("application.apk", _apk_bytes()),
            ("info.json", b'{"base_apk":"missing.apk"}'),
        ],
    )

    with pytest.raises(ApkInspectionError, match="reference does not exist"):
        inspect_android_package(bundle)


def test_rejects_symlink_in_unpacked_apkm(tmp_path: Path) -> None:
    bundle = tmp_path / "unpacked"
    bundle.mkdir()
    target = tmp_path / "target.apk"
    target.write_bytes(_apk_bytes())
    link = bundle / "base.apk"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are not available on this platform")

    with pytest.raises(ApkInspectionError, match="symbolic links"):
        inspect_android_package(bundle)


def test_rejects_unsupported_source(tmp_path: Path) -> None:
    source = tmp_path / "fixture.bin"
    source.write_bytes(_apk_bytes())

    with pytest.raises(ApkInspectionError, match="unsupported package source"):
        inspect_android_package(source)
