"""Deterministic APK content inventory and signing-evidence collection."""

from __future__ import annotations

import hashlib
import re
import stat
import struct
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.tools.static.apk import PackageSourceKind, inspect_android_package

_BUFFER_SIZE = 1024 * 1024
_DEFAULT_MAX_INVENTORY_ENTRIES = 50_000
_DEFAULT_MAX_HASHED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_SIGNING_BLOCK_BYTES = 64 * 1024 * 1024
_MAX_SIGNING_PAIRS = 1024
_MAX_SIGNERS = 32
_MAX_CERTIFICATES_PER_SIGNER = 32
_MAX_SIGNATURES_PER_SIGNER = 64
_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_MIN_SIZE = 22
_EOCD_MAX_COMMENT = 65_535
_APK_SIGNING_BLOCK_MAGIC = b"APK Sig Block 42"
_APK_SIGNATURE_V2_ID = 0x7109871A
_APK_SIGNATURE_V3_ID = 0xF05368C0
_APK_SIGNATURE_V31_ID = 0x1B93AD61
_DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class ApkMetadataError(ValueError):
    """Raised when safe deterministic metadata collection cannot complete."""


class SignatureEvidenceStatus(StrEnum):
    """Observed evidence state; none of these values claims signature validity."""

    RECOGNIZED_SCHEME = "recognized_scheme"
    LEGACY_EVIDENCE = "legacy_evidence"
    UNSUPPORTED_SIGNING_BLOCK = "unsupported_signing_block"
    MALFORMED_SIGNING_BLOCK = "malformed_signing_block"
    NO_RECOGNIZED_EVIDENCE = "no_recognized_evidence"


class SigningScheme(StrEnum):
    V2 = "v2"
    V3 = "v3"
    V31 = "v3.1"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ApkMetadataInput(_StrictModel):
    """Bounded input accepted by :class:`ApkMetadataTool`."""

    path: Path
    max_inventory_entries: int = Field(
        default=_DEFAULT_MAX_INVENTORY_ENTRIES, ge=1, le=100_000
    )
    max_hashed_bytes: int = Field(
        default=_DEFAULT_MAX_HASHED_BYTES,
        ge=1,
        le=8 * 1024 * 1024 * 1024,
    )

    @field_validator("path", mode="before")
    @classmethod
    def accept_path_string(cls, value: object) -> object:
        if isinstance(value, str):
            return Path(value)
        return value


class ContentEntry(_StrictModel):
    """Hash-addressed ZIP entry used for assets, resources, and DEX files."""

    path: str = Field(min_length=1)
    size_bytes: int = Field(ge=0)
    compressed_size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class NativeLibraryEntry(ContentEntry):
    """Native shared library with its APK ABI location."""

    abi: str = Field(min_length=1)
    library_name: str = Field(min_length=1)


class CertificateEvidence(_StrictModel):
    """Fingerprint of bytes carried in a signing-scheme certificate slot."""

    certificate_index: int = Field(ge=0)
    der_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(gt=0)
    der_sequence_valid: bool


class SignatureRecordEvidence(_StrictModel):
    """Fingerprint and algorithm identifier for one signer signature record."""

    signature_index: int = Field(ge=0)
    algorithm_id: int = Field(ge=0, le=0xFFFFFFFF)
    signature_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class SignerEvidence(_StrictModel):
    """Non-verifying evidence extracted from one v2/v3 signer."""

    signer_index: int = Field(ge=0)
    certificates: tuple[CertificateEvidence, ...]
    signatures: tuple[SignatureRecordEvidence, ...]
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key_size_bytes: int = Field(ge=0)
    min_sdk: int | None = Field(default=None, ge=0)
    max_sdk: int | None = Field(default=None, ge=0)


class SigningSchemeEvidence(_StrictModel):
    """One recognized APK Signing Block pair."""

    scheme: SigningScheme
    block_id: int = Field(ge=0, le=0xFFFFFFFF)
    parsed: bool
    signers: tuple[SignerEvidence, ...] = ()
    error: str | None = None


class SigningEvidence(_StrictModel):
    """Conservative signature evidence with an explicit uncertainty state."""

    status: SignatureEvidenceStatus
    signing_block_present: bool
    schemes: tuple[SigningSchemeEvidence, ...] = ()
    unsupported_block_ids: tuple[str, ...] = ()
    legacy_entries: tuple[ContentEntry, ...] = ()
    warnings: tuple[str, ...] = ()


class ApkMetadataResult(_StrictModel):
    """Bounded, deterministic content and signing inventory for one APK."""

    source_path: str = Field(min_length=1)
    apk_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    apk_size_bytes: int = Field(ge=0)
    archive_entry_count: int = Field(ge=1)
    categorized_entry_count: int = Field(ge=0)
    assets: tuple[ContentEntry, ...] = ()
    resources: tuple[ContentEntry, ...] = ()
    native_libraries: tuple[NativeLibraryEntry, ...] = ()
    dex_files: tuple[ContentEntry, ...] = ()
    signing: SigningEvidence
    warnings: tuple[str, ...] = ()


class ApkMetadataTool(BaseTool[ApkMetadataInput]):
    """Tool adapter for safe APK content/signing metadata collection."""

    name = "apk_metadata"
    description = "Inventory APK static content and collect signing evidence."
    version = "1.0.0"
    input_model = ApkMetadataInput

    def execute(
        self, context: ToolContext, arguments: ApkMetadataInput
    ) -> ToolExecution:
        del context
        result = inspect_apk_metadata(
            arguments.path,
            max_inventory_entries=arguments.max_inventory_entries,
            max_hashed_bytes=arguments.max_hashed_bytes,
        )
        return ToolExecution(output=result.model_dump(mode="json"))


def inspect_apk_metadata(
    path: Path | str,
    *,
    max_inventory_entries: int = _DEFAULT_MAX_INVENTORY_ENTRIES,
    max_hashed_bytes: int = _DEFAULT_MAX_HASHED_BYTES,
) -> ApkMetadataResult:
    """Inspect one APK without extracting it or asserting signature validity."""

    if not 1 <= max_inventory_entries <= 100_000:
        raise ApkMetadataError("max_inventory_entries must be between 1 and 100000")
    if not 1 <= max_hashed_bytes <= 8 * 1024 * 1024 * 1024:
        raise ApkMetadataError("max_hashed_bytes is outside the supported range")

    source = Path(path)
    inspection = inspect_android_package(source, allow_extensionless_apk=True)
    if inspection.source_kind is not PackageSourceKind.APK:
        raise ApkMetadataError(
            "APK metadata requires one .apk; inspect/import APKM members first"
        )

    try:
        with ZipFile(source) as archive:
            members = _safe_member_index(archive, str(source))
            categories = _categorize_members(members)
            inventory_members = _unique_inventory_members(categories)
            if len(inventory_members) > max_inventory_entries:
                raise ApkMetadataError(
                    "APK categorized inventory exceeds max_inventory_entries"
                )
            total_hashed_bytes = sum(member.file_size for member in inventory_members)
            if total_hashed_bytes > max_hashed_bytes:
                raise ApkMetadataError("APK inventory exceeds max_hashed_bytes")

            hashes = {
                member.filename: _hash_member(archive, member, str(source))
                for member in inventory_members
            }
            assets = tuple(
                _content_entry(member, hashes[member.filename])
                for member in categories.assets
            )
            resources = tuple(
                _content_entry(member, hashes[member.filename])
                for member in categories.resources
            )
            dex_files = tuple(
                _content_entry(member, hashes[member.filename])
                for member in categories.dex_files
            )
            native_libraries = tuple(
                _native_entry(member, hashes[member.filename])
                for member in categories.native_libraries
            )
            legacy_entries = tuple(
                _content_entry(member, hashes[member.filename])
                for member in categories.legacy_signature_entries
            )
    except ApkMetadataError:
        raise
    except (BadZipFile, LargeZipFile, OSError, RuntimeError) as exc:
        raise ApkMetadataError(f"cannot inventory APK {source}: {exc}") from exc

    signing = _collect_signing_evidence(source, legacy_entries)
    warnings = list(signing.warnings)
    if categories.nonstandard_lib_entries:
        warnings.append(
            "Entries under lib/ that are not standard lib/<abi>/*.so paths were ignored."
        )
    return ApkMetadataResult(
        source_path=str(source),
        apk_sha256=inspection.base_apk.sha256,
        apk_size_bytes=inspection.base_apk.size_bytes,
        archive_entry_count=inspection.base_apk.archive_entry_count,
        categorized_entry_count=len(inventory_members),
        assets=assets,
        resources=resources,
        native_libraries=native_libraries,
        dex_files=dex_files,
        signing=signing,
        warnings=tuple(warnings),
    )


class _Categories:
    def __init__(self) -> None:
        self.assets: list[ZipInfo] = []
        self.resources: list[ZipInfo] = []
        self.native_libraries: list[ZipInfo] = []
        self.dex_files: list[ZipInfo] = []
        self.legacy_signature_entries: list[ZipInfo] = []
        self.nonstandard_lib_entries: list[ZipInfo] = []


def _categorize_members(members: Mapping[str, ZipInfo]) -> _Categories:
    categories = _Categories()
    for name, member in members.items():
        if member.is_dir():
            continue
        parts = PurePosixPath(name).parts
        upper_name = name.upper()
        if parts[0] == "assets" and len(parts) > 1:
            categories.assets.append(member)
        elif parts[0] == "res" and len(parts) > 1 or name == "resources.arsc":
            categories.resources.append(member)
        elif parts[0] == "lib":
            if len(parts) == 3 and parts[2].endswith(".so"):
                categories.native_libraries.append(member)
            else:
                categories.nonstandard_lib_entries.append(member)
        elif _DEX_NAME.fullmatch(name):
            categories.dex_files.append(member)

        if upper_name.startswith("META-INF/") and upper_name.endswith(
            (".MF", ".SF", ".RSA", ".DSA", ".EC")
        ):
            categories.legacy_signature_entries.append(member)

    for values in (
        categories.assets,
        categories.resources,
        categories.native_libraries,
        categories.dex_files,
        categories.legacy_signature_entries,
        categories.nonstandard_lib_entries,
    ):
        values.sort(key=lambda member: _name_sort_key(member.filename))
    return categories


def _unique_inventory_members(categories: _Categories) -> list[ZipInfo]:
    by_name = {
        member.filename: member
        for group in (
            categories.assets,
            categories.resources,
            categories.native_libraries,
            categories.dex_files,
            categories.legacy_signature_entries,
        )
        for member in group
    }
    return [by_name[name] for name in sorted(by_name, key=_name_sort_key)]


def _safe_member_index(archive: ZipFile, label: str) -> dict[str, ZipInfo]:
    members: dict[str, ZipInfo] = {}
    for member in archive.infolist():
        name = _validate_member_name(member.filename, label)
        if name in members:
            raise ApkMetadataError(f"duplicate ZIP member {name!r}: {label}")
        if member.flag_bits & 0x1:
            raise ApkMetadataError(f"encrypted ZIP member {name!r}: {label}")
        unix_mode = member.external_attr >> 16
        if unix_mode and stat.S_ISLNK(unix_mode):
            raise ApkMetadataError(f"symbolic-link ZIP member {name!r}: {label}")
        members[name] = member
    return members


def _validate_member_name(name: str, label: str) -> str:
    if not name or "\x00" in name or "\\" in name:
        raise ApkMetadataError(f"unsafe ZIP member name {name!r}: {label}")
    if name.startswith("/") or _DRIVE_PREFIX.match(name):
        raise ApkMetadataError(f"unsafe ZIP member name {name!r}: {label}")
    without_trailing_slash = name[:-1] if name.endswith("/") else name
    parts = PurePosixPath(without_trailing_slash).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ApkMetadataError(f"unsafe ZIP member name {name!r}: {label}")
    canonical = "/".join(parts)
    expected = canonical + ("/" if name.endswith("/") else "")
    if name != expected:
        raise ApkMetadataError(f"non-canonical ZIP member name {name!r}: {label}")
    return canonical


def _hash_member(archive: ZipFile, member: ZipInfo, label: str) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(member) as stream:
            while block := stream.read(_BUFFER_SIZE):
                digest.update(block)
                size += len(block)
    except (BadZipFile, OSError, RuntimeError) as exc:
        raise ApkMetadataError(
            f"cannot read ZIP member {member.filename!r}: {label}: {exc}"
        ) from exc
    if size != member.file_size:
        raise ApkMetadataError(
            f"ZIP member size mismatch for {member.filename!r}: {label}"
        )
    return digest.hexdigest()


def _content_entry(member: ZipInfo, sha256: str) -> ContentEntry:
    return ContentEntry(
        path=member.filename,
        size_bytes=member.file_size,
        compressed_size_bytes=member.compress_size,
        sha256=sha256,
    )


def _native_entry(member: ZipInfo, sha256: str) -> NativeLibraryEntry:
    parts = PurePosixPath(member.filename).parts
    return NativeLibraryEntry(
        path=member.filename,
        size_bytes=member.file_size,
        compressed_size_bytes=member.compress_size,
        sha256=sha256,
        abi=parts[1],
        library_name=parts[2],
    )


class _SigningBlockError(ValueError):
    pass


class _SigningBlockScan:
    def __init__(
        self,
        *,
        present: bool,
        schemes: tuple[SigningSchemeEvidence, ...] = (),
        unsupported_ids: tuple[str, ...] = (),
    ) -> None:
        self.present = present
        self.schemes = schemes
        self.unsupported_ids = unsupported_ids


def _collect_signing_evidence(
    path: Path, legacy_entries: tuple[ContentEntry, ...]
) -> SigningEvidence:
    try:
        scan = _scan_apk_signing_block(path)
    except (OSError, _SigningBlockError) as exc:
        warning = (
            f"APK Signing Block is malformed or could not be parsed: {exc}. "
            "No signature validity conclusion was made."
        )
        return SigningEvidence(
            status=SignatureEvidenceStatus.MALFORMED_SIGNING_BLOCK,
            signing_block_present=True,
            legacy_entries=legacy_entries,
            warnings=(warning,),
        )

    scheme_errors = [scheme for scheme in scan.schemes if not scheme.parsed]
    parsed_schemes = [scheme for scheme in scan.schemes if scheme.parsed]
    warnings: list[str] = []
    if parsed_schemes:
        status = SignatureEvidenceStatus.RECOGNIZED_SCHEME
        warnings.append(
            "Signing certificate/signature bytes were fingerprinted, but signatures, "
            "certificate trust, and signer identity were not cryptographically verified."
        )
        if scheme_errors:
            warnings.append(
                "At least one recognized signing-scheme pair was malformed."
            )
    elif scheme_errors:
        status = SignatureEvidenceStatus.MALFORMED_SIGNING_BLOCK
        warnings.append(
            "A recognized APK signing-scheme pair was malformed; signature status "
            "cannot be determined."
        )
    elif scan.present or scan.unsupported_ids:
        status = SignatureEvidenceStatus.UNSUPPORTED_SIGNING_BLOCK
        warnings.append(
            "Signing evidence contains unsupported structures or block IDs; no "
            "supported v2/v3 certificate evidence was parsed and signature status "
            "cannot be determined."
        )
    elif _has_legacy_signature_container(legacy_entries):
        status = SignatureEvidenceStatus.LEGACY_EVIDENCE
        warnings.append(
            "META-INF signature-container files were fingerprinted, but the JAR/v1 "
            "signature was not cryptographically verified."
        )
    else:
        status = SignatureEvidenceStatus.NO_RECOGNIZED_EVIDENCE
        warnings.append(
            "No recognized signature evidence was found; this does not establish "
            "that the APK is unsigned."
        )

    return SigningEvidence(
        status=status,
        signing_block_present=scan.present,
        schemes=scan.schemes,
        unsupported_block_ids=scan.unsupported_ids,
        legacy_entries=legacy_entries,
        warnings=tuple(warnings),
    )


def _has_legacy_signature_container(entries: tuple[ContentEntry, ...]) -> bool:
    return any(
        entry.path.upper().endswith((".RSA", ".DSA", ".EC")) for entry in entries
    )


def _scan_apk_signing_block(path: Path) -> _SigningBlockScan:
    with path.open("rb") as stream:
        stream.seek(0, 2)
        file_size = stream.tell()
        eocd_offset = _find_eocd(stream, file_size)
        stream.seek(eocd_offset + 16)
        central_directory_offset = struct.unpack("<I", _read_exact(stream, 4))[0]
        if central_directory_offset == 0xFFFFFFFF:
            return _SigningBlockScan(
                present=False,
                unsupported_ids=("zip64",),
            )
        if central_directory_offset < 24:
            return _SigningBlockScan(present=False)

        stream.seek(central_directory_offset - 24)
        footer = _read_exact(stream, 24)
        if footer[8:] != _APK_SIGNING_BLOCK_MAGIC:
            return _SigningBlockScan(present=False)

        block_size = struct.unpack_from("<Q", footer, 0)[0]
        if block_size < 24:
            raise _SigningBlockError("signing block size is too small")
        total_size = block_size + 8
        if total_size > _MAX_SIGNING_BLOCK_BYTES:
            raise _SigningBlockError("signing block exceeds the bounded read limit")
        if total_size > central_directory_offset:
            raise _SigningBlockError("signing block starts before the APK")
        block_start = central_directory_offset - total_size
        stream.seek(block_start)
        block = _read_exact(stream, total_size)

    header_size = struct.unpack_from("<Q", block, 0)[0]
    if header_size != block_size:
        raise _SigningBlockError("signing block header/footer sizes differ")
    if block[-16:] != _APK_SIGNING_BLOCK_MAGIC:
        raise _SigningBlockError("signing block magic is invalid")
    return _parse_signing_pairs(memoryview(block)[8:-24])


def _find_eocd(stream: IO[bytes], file_size: int) -> int:
    read_size = min(file_size, _EOCD_MIN_SIZE + _EOCD_MAX_COMMENT)
    if read_size < _EOCD_MIN_SIZE:
        raise _SigningBlockError("APK is too small to contain ZIP EOCD")
    stream.seek(file_size - read_size)
    tail = _read_exact(stream, read_size)
    search_end = len(tail)
    while search_end >= _EOCD_MIN_SIZE:
        offset = tail.rfind(_EOCD_SIGNATURE, 0, search_end)
        if offset < 0:
            break
        if offset + _EOCD_MIN_SIZE <= len(tail):
            comment_size = struct.unpack_from("<H", tail, offset + 20)[0]
            if offset + _EOCD_MIN_SIZE + comment_size == len(tail):
                return file_size - read_size + offset
        search_end = offset
    raise _SigningBlockError("ZIP EOCD could not be located")


def _parse_signing_pairs(pairs: memoryview) -> _SigningBlockScan:
    reader = _ByteReader(pairs)
    schemes: list[SigningSchemeEvidence] = []
    unsupported_ids: list[str] = []
    seen_ids: set[int] = set()
    pair_count = 0
    scheme_ids = {
        _APK_SIGNATURE_V2_ID: SigningScheme.V2,
        _APK_SIGNATURE_V3_ID: SigningScheme.V3,
        _APK_SIGNATURE_V31_ID: SigningScheme.V31,
    }
    while reader.remaining:
        pair_count += 1
        if pair_count > _MAX_SIGNING_PAIRS:
            raise _SigningBlockError("signing block contains too many pairs")
        pair_size = reader.read_u64("pair size")
        if pair_size < 4 or pair_size > reader.remaining:
            raise _SigningBlockError("signing block pair has an invalid size")
        pair = _ByteReader(reader.read_exact(pair_size, "pair"))
        block_id = pair.read_u32("pair ID")
        value = pair.read_exact(pair.remaining, "pair value")
        if block_id in seen_ids:
            raise _SigningBlockError(f"duplicate signing block ID 0x{block_id:08x}")
        seen_ids.add(block_id)
        scheme = scheme_ids.get(block_id)
        if scheme is None:
            unsupported_ids.append(f"0x{block_id:08x}")
            continue
        try:
            signers = _parse_scheme_value(value, scheme)
            if not signers or not any(signer.certificates for signer in signers):
                raise _SigningBlockError("scheme contains no certificate evidence")
            schemes.append(
                SigningSchemeEvidence(
                    scheme=scheme,
                    block_id=block_id,
                    parsed=True,
                    signers=signers,
                )
            )
        except _SigningBlockError as exc:
            schemes.append(
                SigningSchemeEvidence(
                    scheme=scheme,
                    block_id=block_id,
                    parsed=False,
                    error=str(exc),
                )
            )
    return _SigningBlockScan(
        present=True,
        schemes=tuple(schemes),
        unsupported_ids=tuple(sorted(unsupported_ids)),
    )


def _parse_scheme_value(
    value: memoryview, scheme: SigningScheme
) -> tuple[SignerEvidence, ...]:
    outer = _ByteReader(value)
    signers_blob = outer.read_length_prefixed("signers")
    outer.require_end("signing-scheme value")
    signers_reader = _ByteReader(signers_blob)
    signers: list[SignerEvidence] = []
    while signers_reader.remaining:
        if len(signers) >= _MAX_SIGNERS:
            raise _SigningBlockError("scheme contains too many signers")
        signer_blob = signers_reader.read_length_prefixed("signer")
        signers.append(_parse_signer(signer_blob, scheme, len(signers)))
    return tuple(signers)


def _parse_signer(
    signer_blob: memoryview, scheme: SigningScheme, signer_index: int
) -> SignerEvidence:
    signer = _ByteReader(signer_blob)
    signed_data = signer.read_length_prefixed("signed data")
    min_sdk: int | None = None
    max_sdk: int | None = None
    if scheme in {SigningScheme.V3, SigningScheme.V31}:
        min_sdk = signer.read_u32("minimum SDK")
        max_sdk = signer.read_u32("maximum SDK")
    signatures_blob = signer.read_length_prefixed("signatures")
    public_key = signer.read_length_prefixed("public key")
    signer.require_end("signer")

    signed_reader = _ByteReader(signed_data)
    signed_reader.read_length_prefixed("digests")
    certificates_blob = signed_reader.read_length_prefixed("certificates")
    certificates = _parse_certificates(certificates_blob)
    signatures = _parse_signatures(signatures_blob)
    return SignerEvidence(
        signer_index=signer_index,
        certificates=certificates,
        signatures=signatures,
        public_key_sha256=hashlib.sha256(public_key).hexdigest(),
        public_key_size_bytes=len(public_key),
        min_sdk=min_sdk,
        max_sdk=max_sdk,
    )


def _parse_certificates(blob: memoryview) -> tuple[CertificateEvidence, ...]:
    reader = _ByteReader(blob)
    certificates: list[CertificateEvidence] = []
    while reader.remaining:
        if len(certificates) >= _MAX_CERTIFICATES_PER_SIGNER:
            raise _SigningBlockError("signer contains too many certificates")
        certificate = reader.read_length_prefixed("certificate")
        if not certificate:
            raise _SigningBlockError("signer contains an empty certificate")
        certificates.append(
            CertificateEvidence(
                certificate_index=len(certificates),
                der_sha256=hashlib.sha256(certificate).hexdigest(),
                size_bytes=len(certificate),
                der_sequence_valid=_is_complete_der_sequence(certificate),
            )
        )
    return tuple(certificates)


def _parse_signatures(blob: memoryview) -> tuple[SignatureRecordEvidence, ...]:
    reader = _ByteReader(blob)
    signatures: list[SignatureRecordEvidence] = []
    while reader.remaining:
        if len(signatures) >= _MAX_SIGNATURES_PER_SIGNER:
            raise _SigningBlockError("signer contains too many signatures")
        record = _ByteReader(reader.read_length_prefixed("signature record"))
        algorithm_id = record.read_u32("signature algorithm ID")
        signature = record.read_length_prefixed("signature bytes")
        record.require_end("signature record")
        signatures.append(
            SignatureRecordEvidence(
                signature_index=len(signatures),
                algorithm_id=algorithm_id,
                signature_sha256=hashlib.sha256(signature).hexdigest(),
                size_bytes=len(signature),
            )
        )
    return tuple(signatures)


def _is_complete_der_sequence(value: memoryview) -> bool:
    if len(value) < 2 or value[0] != 0x30:
        return False
    first_length = value[1]
    if first_length < 0x80:
        header_size = 2
        content_size = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or 2 + length_bytes > len(value):
            return False
        header_size = 2 + length_bytes
        content_size = int.from_bytes(value[2:header_size], "big")
    return header_size + content_size == len(value)


class _ByteReader:
    def __init__(self, value: memoryview) -> None:
        self.value = value
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.value) - self.offset

    def read_exact(self, size: int, label: str) -> memoryview:
        if size < 0 or size > self.remaining:
            raise _SigningBlockError(f"truncated {label}")
        start = self.offset
        self.offset += size
        return self.value[start : start + size]

    def read_u32(self, label: str) -> int:
        return int.from_bytes(self.read_exact(4, label), "little")

    def read_u64(self, label: str) -> int:
        return int.from_bytes(self.read_exact(8, label), "little")

    def read_length_prefixed(self, label: str) -> memoryview:
        size = self.read_u32(f"{label} length")
        return self.read_exact(size, label)

    def require_end(self, label: str) -> None:
        if self.remaining:
            raise _SigningBlockError(f"unexpected trailing bytes in {label}")


def _read_exact(stream: IO[bytes], size: int) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise _SigningBlockError("unexpected end of file")
    return value


def _name_sort_key(name: str) -> tuple[str, str]:
    return name.casefold(), name
