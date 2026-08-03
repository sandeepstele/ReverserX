from __future__ import annotations

import hashlib
import io
import struct
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pydantic import ValidationError

from reverserx.tools.base import ToolContext
from reverserx.tools.static.apk import ApkInspectionError
from reverserx.tools.static.metadata import (
    ApkMetadataError,
    ApkMetadataInput,
    ApkMetadataTool,
    SignatureEvidenceStatus,
    SigningScheme,
    inspect_apk_metadata,
)

_MAGIC = b"APK Sig Block 42"
_V2_ID = 0x7109871A


def _write_apk(path: Path, members: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"binary-manifest")
        for name, value in members:
            archive.writestr(name, value)
    content = output.getvalue()
    path.write_bytes(content)
    return content


def _lp(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _v2_value(certificate: bytes, signature: bytes = b"signature") -> bytes:
    certificates = _lp(certificate)
    signed_data = _lp(b"") + _lp(certificates) + _lp(b"")
    signature_record = struct.pack("<I", 0x0103) + _lp(signature)
    signatures = _lp(signature_record)
    signer = _lp(signed_data) + _lp(signatures) + _lp(b"public-key")
    return _lp(_lp(signer))


def _add_signing_block(
    unsigned_apk: bytes,
    pairs: list[tuple[int, bytes]],
    *,
    corrupt_header_size: bool = False,
) -> bytes:
    eocd_offset = unsigned_apk.rfind(b"PK\x05\x06")
    assert eocd_offset >= 0
    central_offset = struct.unpack_from("<I", unsigned_apk, eocd_offset + 16)[0]
    pair_bytes = b"".join(
        struct.pack("<Q", len(value) + 4) + struct.pack("<I", block_id) + value
        for block_id, value in pairs
    )
    block_size = len(pair_bytes) + 24
    header_size = block_size + 1 if corrupt_header_size else block_size
    block = (
        struct.pack("<Q", header_size)
        + pair_bytes
        + struct.pack("<Q", block_size)
        + _MAGIC
    )
    signed = bytearray(
        unsigned_apk[:central_offset] + block + unsigned_apk[central_offset:]
    )
    new_eocd_offset = eocd_offset + len(block)
    struct.pack_into("<I", signed, new_eocd_offset + 16, central_offset + len(block))
    return bytes(signed)


def test_inventories_static_content_deterministically(tmp_path: Path) -> None:
    apk = tmp_path / "fixture.apk"
    dex = b"dex\n035\x00fixture"
    library = b"\x7fELFfixture"
    _write_apk(
        apk,
        [
            ("res/xml/network_security_config.xml", b"<network-security-config/>"),
            ("assets/config.json", b"{}"),
            ("resources.arsc", b"arsc"),
            ("lib/arm64-v8a/libfixture.so", library),
            ("lib/not-standard.txt", b"ignored"),
            ("classes.dex", dex),
            ("classes2.dex", b"second-dex"),
        ],
    )

    first = inspect_apk_metadata(apk)
    second = inspect_apk_metadata(apk)

    assert first == second
    assert [entry.path for entry in first.assets] == ["assets/config.json"]
    assert [entry.path for entry in first.resources] == [
        "res/xml/network_security_config.xml",
        "resources.arsc",
    ]
    assert [entry.path for entry in first.dex_files] == [
        "classes.dex",
        "classes2.dex",
    ]
    assert first.dex_files[0].sha256 == hashlib.sha256(dex).hexdigest()
    assert first.native_libraries[0].abi == "arm64-v8a"
    assert first.native_libraries[0].library_name == "libfixture.so"
    assert first.native_libraries[0].sha256 == hashlib.sha256(library).hexdigest()
    assert "not standard" in first.warnings[-1]


def test_accepts_verified_extensionless_artifact_blob(tmp_path: Path) -> None:
    blob = tmp_path / "blob"
    content = _write_apk(blob, [("classes.dex", b"dex")])

    result = inspect_apk_metadata(blob)

    assert result.apk_sha256 == hashlib.sha256(content).hexdigest()
    assert result.dex_files[0].path == "classes.dex"


def test_no_signature_evidence_does_not_claim_unsigned(tmp_path: Path) -> None:
    apk = tmp_path / "unsigned-looking.apk"
    _write_apk(apk, [("classes.dex", b"dex")])

    result = inspect_apk_metadata(apk)

    assert result.signing.status is SignatureEvidenceStatus.NO_RECOGNIZED_EVIDENCE
    assert result.signing.signing_block_present is False
    assert "does not establish" in result.signing.warnings[0]


def test_collects_legacy_signature_evidence_without_verifying(tmp_path: Path) -> None:
    apk = tmp_path / "legacy.apk"
    certificate_container = b"pkcs7-container"
    _write_apk(
        apk,
        [
            ("META-INF/MANIFEST.MF", b"manifest"),
            ("META-INF/CERT.SF", b"signature-file"),
            ("META-INF/CERT.RSA", certificate_container),
        ],
    )

    result = inspect_apk_metadata(apk)

    assert result.signing.status is SignatureEvidenceStatus.LEGACY_EVIDENCE
    assert [entry.path for entry in result.signing.legacy_entries] == [
        "META-INF/CERT.RSA",
        "META-INF/CERT.SF",
        "META-INF/MANIFEST.MF",
    ]
    assert (
        result.signing.legacy_entries[0].sha256
        == hashlib.sha256(certificate_container).hexdigest()
    )
    assert "not cryptographically verified" in result.signing.warnings[0]


def test_extracts_v2_signer_certificate_and_signature_fingerprints(
    tmp_path: Path,
) -> None:
    apk = tmp_path / "v2.apk"
    certificate = b"\x30\x03\x02\x01\x01"
    signature = b"synthetic-signature"
    unsigned = _write_apk(apk, [("classes.dex", b"dex")])
    apk.write_bytes(
        _add_signing_block(unsigned, [(_V2_ID, _v2_value(certificate, signature))])
    )

    result = inspect_apk_metadata(apk)

    assert result.signing.status is SignatureEvidenceStatus.RECOGNIZED_SCHEME
    assert result.signing.signing_block_present is True
    scheme = result.signing.schemes[0]
    assert scheme.scheme is SigningScheme.V2
    assert scheme.parsed is True
    signer = scheme.signers[0]
    assert signer.certificates[0].der_sha256 == hashlib.sha256(certificate).hexdigest()
    assert signer.certificates[0].der_sequence_valid is True
    assert signer.signatures[0].algorithm_id == 0x0103
    assert (
        signer.signatures[0].signature_sha256 == hashlib.sha256(signature).hexdigest()
    )
    assert "not cryptographically verified" in result.signing.warnings[0]


def test_reports_unsupported_signing_block_without_guessing(tmp_path: Path) -> None:
    apk = tmp_path / "unsupported.apk"
    unsigned = _write_apk(apk, [("classes.dex", b"dex")])
    apk.write_bytes(_add_signing_block(unsigned, [(0x12345678, b"opaque")]))

    result = inspect_apk_metadata(apk)

    assert result.signing.status is SignatureEvidenceStatus.UNSUPPORTED_SIGNING_BLOCK
    assert result.signing.unsupported_block_ids == ("0x12345678",)
    assert "cannot be determined" in result.signing.warnings[0]


def test_reports_malformed_signing_block_as_evidence_state(tmp_path: Path) -> None:
    apk = tmp_path / "malformed-signing.apk"
    unsigned = _write_apk(apk, [("classes.dex", b"dex")])
    apk.write_bytes(
        _add_signing_block(
            unsigned,
            [(_V2_ID, _v2_value(b"\x30\x00"))],
            corrupt_header_size=True,
        )
    )

    result = inspect_apk_metadata(apk)

    assert result.signing.status is SignatureEvidenceStatus.MALFORMED_SIGNING_BLOCK
    assert result.signing.signing_block_present is True
    assert "No signature validity conclusion" in result.signing.warnings[0]


def test_rejects_inventory_count_and_hash_byte_limits(tmp_path: Path) -> None:
    apk = tmp_path / "limits.apk"
    _write_apk(
        apk,
        [
            ("assets/one", b"1"),
            ("assets/two", b"22"),
            ("classes.dex", b"dex"),
        ],
    )

    with pytest.raises(ApkMetadataError, match="max_inventory_entries"):
        inspect_apk_metadata(apk, max_inventory_entries=1)
    with pytest.raises(ApkMetadataError, match="max_hashed_bytes"):
        inspect_apk_metadata(apk, max_hashed_bytes=2)


@pytest.mark.parametrize("member", ["../assets/a", "assets\\a"])
def test_rejects_unsafe_archive_members(tmp_path: Path, member: str) -> None:
    apk = tmp_path / "unsafe.apk"
    _write_apk(apk, [(member, b"unsafe")])

    with pytest.raises(ApkInspectionError, match="unsafe ZIP member"):
        inspect_apk_metadata(apk)


def test_rejects_duplicate_and_malformed_apks(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.apk"
    with pytest.warns(UserWarning, match="Duplicate name"):
        _write_apk(
            duplicate,
            [("assets/a", b"one"), ("assets/a", b"two")],
        )
    malformed = tmp_path / "malformed.apk"
    malformed.write_bytes(b"not-a-zip")

    with pytest.raises(ApkInspectionError, match="duplicate ZIP member"):
        inspect_apk_metadata(duplicate)
    with pytest.raises(ApkInspectionError, match="malformed APK"):
        inspect_apk_metadata(malformed)


def test_tool_input_is_strict_and_output_is_serializable(tmp_path: Path) -> None:
    apk = tmp_path / "fixture.apk"
    _write_apk(apk, [("classes.dex", b"dex")])
    arguments = ApkMetadataInput.model_validate({"path": str(apk)})

    execution = ApkMetadataTool().execute(
        ToolContext(project_id="prj_fixture", data_dir=tmp_path), arguments
    )

    assert execution.output["apk_sha256"]
    assert execution.output["signing"]["status"] == "no_recognized_evidence"
    with pytest.raises(ValidationError):
        ApkMetadataInput.model_validate({"path": str(apk), "extra": True})
