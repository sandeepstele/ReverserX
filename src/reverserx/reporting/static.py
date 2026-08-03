"""Deterministic Markdown reporting for Android static analysis."""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution
from reverserx.tools.static.apk import ApkInspectionResult
from reverserx.tools.static.jadx import JadxResult
from reverserx.tools.static.manifest import ManifestAnalysis
from reverserx.tools.static.metadata import (
    ApkMetadataResult,
    ContentEntry,
    NativeLibraryEntry,
    SigningSchemeEvidence,
)
from reverserx.tools.static.obfuscation import ObfuscationReport

_MAX_LARGE_INVENTORY_ROWS = 250
_JADX_ERROR_COUNT_PATTERN = re.compile(
    r"finished\s+with\s+errors,?\s*count:\s*(?P<count>[0-9]+)", re.IGNORECASE
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ReportProject(_StrictModel):
    """Project metadata and the authorization statement shown in a report."""

    project_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=500)
    slug: str | None = Field(default=None, max_length=200)
    description: str = Field(default="", max_length=10_000)
    analysis_goal: str | None = Field(default=None, max_length=10_000)
    authorization_confirmed: bool = False
    authorized_scope: tuple[str, ...] = Field(default=(), max_length=1_000)


class ContextReportSummary(_StrictModel):
    """Normalized index and summary metrics from any context backend."""

    index_id: str | None = Field(default=None, max_length=200)
    source_root: str | None = Field(default=None, max_length=4_096)
    source_file_count: int | None = Field(default=None, ge=0)
    skipped_source_file_count: int = Field(default=0, ge=0)
    oversized_fallback_source_file_count: int = Field(default=0, ge=0)
    source_index_warning_count: int = Field(default=0, ge=0)
    source_index_warnings: tuple[str, ...] = Field(default=(), max_length=100)
    chunk_count: int = Field(default=0, ge=0)
    summary_count: int = Field(default=0, ge=0)
    vector_document_count: int | None = Field(default=None, ge=0)
    embedding_provider: str | None = Field(default=None, max_length=500)
    project_summary: str | None = Field(default=None, max_length=100_000)


class SourceReference(_StrictModel):
    """Evidence-backed source location suitable for a static report."""

    path: str = Field(min_length=1, max_length=4_096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str | None = Field(default=None, max_length=4_096)
    summary: str = Field(min_length=1, max_length=100_000)
    chunk_id: str | None = Field(default=None, max_length=500)
    tool_run_id: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


class StaticReportInput(_StrictModel):
    """Strict normalized inputs for deterministic static-report rendering.

    Tool outputs may be supplied either as their typed models or as JSON-like
    dictionaries returned by ``ToolExecution.output``.
    """

    schema_version: Literal["1.0"] = "1.0"
    project: ReportProject
    apk: ApkInspectionResult
    apk_metadata: ApkMetadataResult | None = None
    jadx: JadxResult | None = None
    manifest: ManifestAnalysis | None = None
    obfuscation: ObfuscationReport | None = None
    context: ContextReportSummary | None = None
    source_references: tuple[SourceReference, ...] = Field(
        default=(), max_length=10_000
    )
    tool_run_ids: tuple[str, ...] = Field(default=(), max_length=10_000)
    limitations: tuple[str, ...] = Field(default=(), max_length=1_000)

    @field_validator("project", mode="before")
    @classmethod
    def parse_project(cls, value: object) -> object:
        return _coerce_model(value, ReportProject)

    @field_validator("apk", mode="before")
    @classmethod
    def parse_apk(cls, value: object) -> object:
        return _coerce_model(value, ApkInspectionResult)

    @field_validator("apk_metadata", mode="before")
    @classmethod
    def parse_apk_metadata(cls, value: object) -> object:
        return _coerce_model(value, ApkMetadataResult)

    @field_validator("jadx", mode="before")
    @classmethod
    def parse_jadx(cls, value: object) -> object:
        return _coerce_model(value, JadxResult)

    @field_validator("manifest", mode="before")
    @classmethod
    def parse_manifest(cls, value: object) -> object:
        return _coerce_model(value, ManifestAnalysis)

    @field_validator("obfuscation", mode="before")
    @classmethod
    def parse_obfuscation(cls, value: object) -> object:
        return _coerce_model(value, ObfuscationReport)

    @field_validator("context", mode="before")
    @classmethod
    def parse_context(cls, value: object) -> object:
        return _coerce_model(value, ContextReportSummary)

    @field_validator("source_references", mode="before")
    @classmethod
    def parse_source_references(cls, value: object) -> object:
        if isinstance(value, (list, tuple)):
            return tuple(_coerce_model(item, SourceReference) for item in value)
        return value

    @field_validator("tool_run_ids", "limitations", mode="before")
    @classmethod
    def accept_json_arrays(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @model_validator(mode="after")
    def validate_apk_metadata_identity(self) -> Self:
        if self.apk_metadata is None:
            return self
        base = self.apk.base_apk
        if self.apk_metadata.apk_sha256 != base.sha256:
            raise ValueError("APK metadata SHA-256 does not match the base APK")
        if self.apk_metadata.apk_size_bytes != base.size_bytes:
            raise ValueError("APK metadata size does not match the base APK")
        return self


class ReportSection(StrEnum):
    PROJECT = "project"
    PACKAGE = "package-inventory"
    APK_METADATA = "apk-static-metadata"
    JADX = "decompilation"
    MANIFEST = "manifest-analysis"
    OBFUSCATION = "obfuscation-assessment"
    CONTEXT = "context-index"
    SOURCE_EVIDENCE = "source-evidence"
    PROVENANCE = "provenance"
    LIMITATIONS = "limitations"


class StaticReportResult(_StrictModel):
    """Rendered Markdown plus deterministic verification metadata."""

    schema_version: Literal["1.0"] = "1.0"
    markdown: str = Field(min_length=1)
    markdown_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    included_sections: tuple[ReportSection, ...]
    missing_sections: tuple[ReportSection, ...]
    evidence_reference_count: int = Field(ge=0)
    tool_run_count: int = Field(ge=0)


class StaticReportError(ValueError):
    """Raised when report inputs conflict with the execution context."""


class StaticReportTool(BaseTool[StaticReportInput]):
    """Tool adapter for orchestration through the normal registry boundary."""

    name = "static_report"
    description = "Render a deterministic evidence-linked static-analysis report."
    version = "1.0.0"
    input_model = StaticReportInput

    def execute(
        self, context: ToolContext, arguments: StaticReportInput
    ) -> ToolExecution:
        if context.project_id != arguments.project.project_id:
            raise StaticReportError(
                "report project does not match the tool execution context"
            )
        result = render_static_report(arguments)
        return ToolExecution(output=result.model_dump(mode="json"))


def render_static_report(report: StaticReportInput) -> StaticReportResult:
    """Render a stable Markdown report without timestamps or environment state."""

    lines: list[str] = [
        "# ReverserX Static Analysis Report",
        "",
        (
            "> **Scope notice:** This report documents authorized static analysis "
            "only. It does not establish runtime behavior, exploitability, or "
            "production impact. Test only assets and systems covered by explicit "
            "permission."
        ),
        "",
    ]
    included: list[ReportSection] = []
    missing: list[ReportSection] = []

    _render_project(lines, report.project)
    included.append(ReportSection.PROJECT)

    _render_package(lines, report.apk)
    included.append(ReportSection.PACKAGE)

    if report.apk_metadata is None:
        missing.append(ReportSection.APK_METADATA)
    else:
        _render_apk_metadata(lines, report.apk_metadata)
        included.append(ReportSection.APK_METADATA)

    if report.jadx is None:
        missing.append(ReportSection.JADX)
    else:
        _render_jadx(lines, report.jadx)
        included.append(ReportSection.JADX)

    if report.manifest is None:
        missing.append(ReportSection.MANIFEST)
    else:
        _render_manifest(lines, report.manifest)
        included.append(ReportSection.MANIFEST)

    if report.obfuscation is None:
        missing.append(ReportSection.OBFUSCATION)
    else:
        _render_obfuscation(lines, report.obfuscation)
        included.append(ReportSection.OBFUSCATION)

    if report.context is None:
        missing.append(ReportSection.CONTEXT)
    else:
        _render_context(lines, report.context)
        included.append(ReportSection.CONTEXT)

    if not report.source_references:
        missing.append(ReportSection.SOURCE_EVIDENCE)
    else:
        _render_source_references(lines, report.source_references)
        included.append(ReportSection.SOURCE_EVIDENCE)

    tool_run_ids = _tool_run_ids(report)
    _render_provenance(lines, report, tool_run_ids)
    included.append(ReportSection.PROVENANCE)

    _render_limitations(lines, report, tuple(missing), tool_run_ids)
    included.append(ReportSection.LIMITATIONS)

    markdown = "\n".join(lines).rstrip() + "\n"
    digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
    evidence_count = len(report.apk.all_apks) + len(report.source_references)
    if report.apk_metadata is not None:
        evidence_count += _apk_metadata_evidence_count(report.apk_metadata)
    if report.manifest is not None:
        evidence_count += len(report.manifest.permissions)
        evidence_count += len(report.manifest.attack_surface)
    if report.obfuscation is not None:
        evidence_count += len(report.obfuscation.signals)
    return StaticReportResult(
        markdown=markdown,
        markdown_sha256=digest,
        included_sections=tuple(included),
        missing_sections=tuple(missing),
        evidence_reference_count=evidence_count,
        tool_run_count=len(tool_run_ids),
    )


def _render_project(lines: list[str], project: ReportProject) -> None:
    _heading(lines, "Project")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Project ID", project.project_id),
            ("Name", project.name),
            ("Slug", project.slug or "Not supplied"),
            ("Description", project.description or "Not supplied"),
            ("Analysis goal", project.analysis_goal or "Not supplied"),
            (
                "Authorization recorded",
                "Yes" if project.authorization_confirmed else "No",
            ),
        ),
    )
    lines.extend(["", "### Authorized Scope", ""])
    if project.authorized_scope:
        _bullets(lines, _sorted_unique(project.authorized_scope))
    else:
        lines.append("No detailed authorization scope was supplied.")
    lines.append("")


def _render_package(lines: list[str], apk: ApkInspectionResult) -> None:
    _heading(lines, "Package Inventory")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Source", apk.source_path),
            ("Source kind", apk.source_kind.value),
            ("Source SHA-256", apk.source_sha256),
            ("Source size", f"{apk.source_size_bytes} bytes"),
            ("APK count", str(len(apk.all_apks))),
        ),
    )
    lines.extend(["", "### APK Files", ""])
    rows: list[tuple[str, ...]] = []
    descriptors = (
        apk.base_apk,
        *sorted(
            apk.split_apks,
            key=lambda item: (
                item.name.casefold(),
                item.name,
                item.split_id or "",
                item.sha256,
                item.size_bytes,
                item.dex_files,
            ),
        ),
    )
    for descriptor in descriptors:
        rows.append(
            (
                descriptor.role.value,
                descriptor.name,
                descriptor.split_id or "—",
                descriptor.sha256,
                str(descriptor.size_bytes),
                str(len(descriptor.dex_files)),
                "Yes" if descriptor.manifest_present else "No",
            )
        )
    _table(
        lines,
        ("Role", "Name", "Split ID", "SHA-256", "Bytes", "DEX", "Manifest"),
        rows,
    )
    lines.append("")


def _render_apk_metadata(lines: list[str], metadata: ApkMetadataResult) -> None:
    _heading(lines, "APK Static Metadata")
    abis = _sorted_unique(library.abi for library in metadata.native_libraries)
    parsed_schemes = _sorted_unique(
        scheme.scheme.value for scheme in metadata.signing.schemes if scheme.parsed
    )
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Source", metadata.source_path),
            ("APK SHA-256", metadata.apk_sha256),
            ("APK size", f"{metadata.apk_size_bytes} bytes"),
            ("Archive entries", str(metadata.archive_entry_count)),
            ("Categorized entries", str(metadata.categorized_entry_count)),
            ("DEX files", str(len(metadata.dex_files))),
            ("Assets", str(len(metadata.assets))),
            ("Resources", str(len(metadata.resources))),
            ("Native libraries", str(len(metadata.native_libraries))),
            ("Native ABIs", ", ".join(abis) or "None identified"),
            ("Signing evidence status", metadata.signing.status.value),
            (
                "APK Signing Block observed",
                _yes_no(metadata.signing.signing_block_present),
            ),
            ("Parsed signing schemes", ", ".join(parsed_schemes) or "None"),
        ),
    )
    lines.extend(
        [
            "",
            (
                "> **Non-verification notice:** Signing data below records observed "
                "fingerprints and parser evidence only. It does not cryptographically "
                "verify signatures, certificate trust, signer identity, or APK integrity."
            ),
            "",
        ]
    )

    _render_content_entries(
        lines,
        "DEX Files",
        metadata.dex_files,
        "No DEX files were inventoried.",
    )
    _render_content_entries(
        lines,
        "Assets",
        metadata.assets,
        "No asset entries were inventoried.",
        row_limit=_MAX_LARGE_INVENTORY_ROWS,
    )
    _render_content_entries(
        lines,
        "Resources",
        metadata.resources,
        "No resource entries were inventoried.",
        row_limit=_MAX_LARGE_INVENTORY_ROWS,
    )
    _render_native_libraries(lines, metadata.native_libraries)
    _render_signing_evidence(lines, metadata)
    warnings = _sorted_unique((*metadata.warnings, *metadata.signing.warnings))
    _render_diagnostics(lines, warnings, ())
    lines.append("")


def _render_content_entries(
    lines: list[str],
    title: str,
    entries: tuple[ContentEntry, ...],
    empty_message: str,
    *,
    row_limit: int | None = None,
) -> None:
    ordered = tuple(sorted(entries, key=_content_entry_sort_key))
    shown = ordered if row_limit is None else ordered[:row_limit]
    lines.extend(
        [
            f"### {title}",
            "",
            f"Total entries: {len(ordered)}; shown: {len(shown)}.",
            "",
        ]
    )
    _table_or_empty(
        lines,
        ("Path", "SHA-256", "Bytes", "Compressed bytes"),
        (
            (
                entry.path,
                entry.sha256,
                str(entry.size_bytes),
                str(entry.compressed_size_bytes),
            )
            for entry in shown
        ),
        empty_message,
    )
    if len(shown) < len(ordered):
        lines.extend(
            [
                "",
                (
                    f"Showing the first {len(shown)} entries in deterministic order. "
                    "The complete inventory remains in the persisted apk_metadata "
                    "tool output."
                ),
            ]
        )
    lines.append("")


def _render_native_libraries(
    lines: list[str], libraries: tuple[NativeLibraryEntry, ...]
) -> None:
    lines.extend(
        [
            "### Native Libraries",
            "",
            f"Total entries: {len(libraries)}; shown: {len(libraries)}.",
            "",
        ]
    )
    ordered = sorted(
        libraries,
        key=lambda item: (
            item.abi.casefold(),
            item.abi,
            item.library_name.casefold(),
            item.library_name,
            *_content_entry_sort_key(item),
        ),
    )
    _table_or_empty(
        lines,
        ("ABI", "Library", "Path", "SHA-256", "Bytes", "Compressed bytes"),
        (
            (
                library.abi,
                library.library_name,
                library.path,
                library.sha256,
                str(library.size_bytes),
                str(library.compressed_size_bytes),
            )
            for library in ordered
        ),
        "No native libraries were inventoried.",
    )
    lines.append("")


def _render_signing_evidence(lines: list[str], metadata: ApkMetadataResult) -> None:
    signing = metadata.signing
    lines.extend(["### Signing Evidence", ""])
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Status", signing.status.value),
            ("Signing block observed", _yes_no(signing.signing_block_present)),
            (
                "Unsupported block IDs",
                ", ".join(sorted(signing.unsupported_block_ids)) or "None",
            ),
            ("Legacy evidence entries", str(len(signing.legacy_entries))),
        ),
    )

    schemes = tuple(sorted(signing.schemes, key=_signing_scheme_sort_key))
    lines.extend(["", "#### Signing Schemes", ""])
    _table_or_empty(
        lines,
        ("Scheme", "Block ID", "Parsed", "Signers", "Parser error"),
        (
            (
                scheme.scheme.value,
                f"0x{scheme.block_id:08x}",
                _yes_no(scheme.parsed),
                str(len(scheme.signers)),
                scheme.error or "—",
            )
            for scheme in schemes
        ),
        "No recognized v2/v3 signing-scheme records were inventoried.",
    )

    signer_rows: list[tuple[str, ...]] = []
    certificate_rows: list[tuple[str, ...]] = []
    signature_rows: list[tuple[str, ...]] = []
    for scheme in schemes:
        for signer in sorted(scheme.signers, key=lambda item: item.signer_index):
            signer_rows.append(
                (
                    scheme.scheme.value,
                    str(signer.signer_index),
                    _sdk_range(signer.min_sdk, signer.max_sdk),
                    signer.public_key_sha256,
                    str(signer.public_key_size_bytes),
                )
            )
            certificate_rows.extend(
                (
                    scheme.scheme.value,
                    str(signer.signer_index),
                    str(certificate.certificate_index),
                    certificate.der_sha256,
                    str(certificate.size_bytes),
                    _yes_no(certificate.der_sequence_valid),
                )
                for certificate in sorted(
                    signer.certificates, key=lambda item: item.certificate_index
                )
            )
            signature_rows.extend(
                (
                    scheme.scheme.value,
                    str(signer.signer_index),
                    str(signature.signature_index),
                    f"0x{signature.algorithm_id:08x}",
                    signature.signature_sha256,
                    str(signature.size_bytes),
                )
                for signature in sorted(
                    signer.signatures, key=lambda item: item.signature_index
                )
            )

    lines.extend(["", "#### Signers and Public Keys", ""])
    _table_or_empty(
        lines,
        ("Scheme", "Signer", "SDK range", "Public key SHA-256", "Bytes"),
        signer_rows,
        "No parsed signer public-key evidence was inventoried.",
    )
    lines.extend(["", "#### Certificate Fingerprints", ""])
    _table_or_empty(
        lines,
        ("Scheme", "Signer", "Certificate", "DER SHA-256", "Bytes", "Complete DER"),
        certificate_rows,
        "No certificate fingerprints were inventoried.",
    )
    lines.extend(["", "#### Signature Record Fingerprints", ""])
    _table_or_empty(
        lines,
        ("Scheme", "Signer", "Signature", "Algorithm ID", "SHA-256", "Bytes"),
        signature_rows,
        "No signature-record fingerprints were inventoried.",
    )
    lines.extend(["", "#### Legacy META-INF Evidence", ""])
    _table_or_empty(
        lines,
        ("Path", "SHA-256", "Bytes", "Compressed bytes"),
        (
            (
                entry.path,
                entry.sha256,
                str(entry.size_bytes),
                str(entry.compressed_size_bytes),
            )
            for entry in sorted(signing.legacy_entries, key=_content_entry_sort_key)
        ),
        "No legacy META-INF signature-container evidence was inventoried.",
    )
    lines.append("")


def _render_jadx(lines: list[str], jadx: JadxResult) -> None:
    reported_error_count = _reported_jadx_error_count(jadx)
    _heading(lines, "Decompilation")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Status", jadx.status.value),
            ("Cache hit", _yes_no(jadx.cache_hit)),
            ("JADX version", jadx.jadx_version),
            ("APK SHA-256", jadx.apk_sha256),
            ("Cache key", jadx.cache_key),
            ("Output directory", str(jadx.output_dir)),
            ("Source files", str(jadx.source_file_count)),
            ("Resource files", str(jadx.resource_file_count)),
            (
                "Decoded manifest",
                str(jadx.manifest_path) if jadx.manifest_path else "Not available",
            ),
            (
                "Return code",
                str(jadx.return_code) if jadx.return_code is not None else "—",
            ),
            (
                "Reported decompilation errors",
                (
                    str(reported_error_count)
                    if reported_error_count is not None
                    else "Not reported"
                ),
            ),
            ("Duration", f"{jadx.duration_seconds:.3f} seconds"),
            ("Command argv", json.dumps(list(jadx.command), separators=(",", ":"))),
        ),
    )
    _render_diagnostics(lines, jadx.warnings, jadx.errors)
    lines.append("")


def _render_manifest(lines: list[str], manifest: ManifestAnalysis) -> None:
    _heading(lines, "Manifest Analysis")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Manifest", manifest.manifest_path),
            ("Package", manifest.package_name),
            ("Version name", manifest.version_name or "Not supplied"),
            ("Version code", manifest.version_code or "Not supplied"),
            ("Minimum SDK", manifest.min_sdk or "Not supplied"),
            ("Target SDK", manifest.target_sdk or "Not supplied"),
            ("Debuggable", _yes_no(manifest.debuggable)),
            ("Allow backup", _yes_no_unknown(manifest.allow_backup)),
            ("Cleartext traffic", _yes_no_unknown(manifest.uses_cleartext_traffic)),
            ("Component count", str(len(manifest.components))),
            ("Exported attack-surface entries", str(len(manifest.attack_surface))),
        ),
    )
    lines.extend(["", "### Permissions", ""])
    permission_rows = (
        (
            permission.name,
            _yes_no(permission.dangerous),
            str(permission.max_sdk) if permission.max_sdk is not None else "—",
            permission.source_locator,
        )
        for permission in sorted(
            manifest.permissions,
            key=lambda item: (
                item.name,
                item.source_locator,
                item.dangerous,
                item.max_sdk if item.max_sdk is not None else -1,
            ),
        )
    )
    _table_or_empty(
        lines,
        ("Permission", "Dangerous", "Max SDK", "Evidence locator"),
        permission_rows,
        "No declared permissions were found.",
    )
    lines.extend(["", "### Exported Attack Surface", ""])
    attack_rows = (
        (
            entry.kind.value,
            entry.component,
            entry.permission or "None",
            entry.reason,
            entry.source_locator,
        )
        for entry in sorted(
            manifest.attack_surface,
            key=lambda item: (
                item.kind.value,
                item.component,
                item.source_locator,
                item.permission or "",
                item.reason,
            ),
        )
    )
    _table_or_empty(
        lines,
        ("Kind", "Component", "Permission", "Reason", "Evidence locator"),
        attack_rows,
        "No enabled exported components were identified.",
    )
    _render_diagnostics(lines, manifest.warnings, ())
    lines.append("")


def _render_obfuscation(lines: list[str], report: ObfuscationReport) -> None:
    _heading(lines, "Obfuscation Assessment")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Source root", report.source_root),
            ("Classification", report.kind.value),
            ("Confidence", _percent(report.confidence)),
            (
                "Likely products",
                ", ".join(sorted(report.likely_products)) or "None identified",
            ),
            ("Files analyzed", str(report.file_count)),
            ("Classes identified", str(report.class_count)),
            ("Methods identified", str(report.method_count)),
            ("Short-name ratio", _percent(report.short_name_ratio)),
            ("Identifier entropy", f"{report.identifier_entropy:.4f}"),
        ),
    )
    lines.extend(["", "### Signals", ""])
    signal_rows = (
        (
            signal.name,
            _percent(signal.score),
            signal.evidence,
            ", ".join(sorted(signal.locators)) or "—",
        )
        for signal in sorted(
            report.signals, key=lambda item: (item.name, item.evidence, item.locators)
        )
    )
    _table_or_empty(
        lines,
        ("Signal", "Score", "Evidence", "Locators"),
        signal_rows,
        "No obfuscation signals were emitted.",
    )
    _render_diagnostics(lines, report.warnings, ())
    lines.append("")


def _render_context(lines: list[str], context: ContextReportSummary) -> None:
    _heading(lines, "Context Index")
    _table(
        lines,
        ("Field", "Value"),
        (
            ("Index ID", context.index_id or "Not supplied"),
            ("Source root", context.source_root or "Not supplied"),
            (
                "Source files indexed",
                str(context.source_file_count)
                if context.source_file_count is not None
                else "Not supplied",
            ),
            ("Source files skipped", str(context.skipped_source_file_count)),
            (
                "Oversized source fallbacks",
                str(context.oversized_fallback_source_file_count),
            ),
            ("Source index warnings", str(context.source_index_warning_count)),
            ("Chunks", str(context.chunk_count)),
            ("Summaries", str(context.summary_count)),
            (
                "Vector documents",
                str(context.vector_document_count)
                if context.vector_document_count is not None
                else "Not supplied",
            ),
            ("Embedding provider", context.embedding_provider or "Not supplied"),
        ),
    )
    if context.project_summary:
        lines.extend(["", "### Project Summary", "", _inline(context.project_summary)])
    index_warnings = context.source_index_warnings
    omitted_warning_count = max(
        0, context.source_index_warning_count - len(index_warnings)
    )
    if omitted_warning_count:
        index_warnings = (
            *index_warnings,
            f"{omitted_warning_count} additional source-index warnings were omitted",
        )
    _render_diagnostics(lines, index_warnings, ())
    lines.append("")


def _render_source_references(
    lines: list[str], references: tuple[SourceReference, ...]
) -> None:
    _heading(lines, "Source Evidence")
    rows = (
        (
            _source_locator(reference),
            reference.symbol or "—",
            reference.summary,
            reference.chunk_id or "—",
            reference.tool_run_id or "—",
        )
        for reference in sorted(
            references,
            key=lambda item: (
                item.path,
                item.start_line,
                item.end_line,
                item.symbol or "",
                item.chunk_id or "",
                item.tool_run_id or "",
                item.summary,
            ),
        )
    )
    _table(
        lines,
        ("Location", "Symbol", "Summary", "Chunk ID", "Tool run"),
        rows,
    )
    lines.append("")


def _render_provenance(
    lines: list[str], report: StaticReportInput, tool_run_ids: tuple[str, ...]
) -> None:
    _heading(lines, "Evidence and Provenance")
    rows: list[tuple[str, str, str]] = [
        ("Input package", report.apk.source_path, report.apk.source_sha256),
        (
            "Base APK",
            report.apk.base_apk.name,
            report.apk.base_apk.sha256,
        ),
    ]
    rows.extend(
        ("Split APK", split.name, split.sha256)
        for split in sorted(
            report.apk.split_apks,
            key=lambda item: (item.name.casefold(), item.name, item.sha256),
        )
    )
    if report.apk_metadata is not None:
        rows.append(
            (
                "APK static metadata",
                report.apk_metadata.source_path,
                report.apk_metadata.apk_sha256,
            )
        )
    if report.jadx is not None:
        reported_error_count = _reported_jadx_error_count(report.jadx)
        return_code = (
            str(report.jadx.return_code)
            if report.jadx.return_code is not None
            else "unknown"
        )
        rows.append(
            (
                "JADX result",
                (
                    f"version={report.jadx.jadx_version}; "
                    f"status={report.jadx.status.value}; "
                    f"return_code={return_code}; "
                    f"cache_hit={_yes_no(report.jadx.cache_hit)}"
                ),
                report.jadx.cache_key,
            )
        )
        if reported_error_count is not None:
            rows.append(
                (
                    "JADX reported error count",
                    str(reported_error_count),
                    report.jadx.cache_key,
                )
            )
        rows.extend(
            ("JADX warning", warning, report.jadx.cache_key)
            for warning in _sorted_unique(report.jadx.warnings)
        )
        rows.extend(
            ("JADX error", error, report.jadx.cache_key)
            for error in _sorted_unique(report.jadx.errors)
        )
    if report.manifest is not None:
        rows.append(("Decoded manifest", report.manifest.manifest_path, "—"))
    if report.context is not None and report.context.index_id:
        rows.append(("Context index", report.context.index_id, "—"))
    rows.extend(
        ("Source chunk", reference.chunk_id, _source_locator(reference))
        for reference in sorted(
            report.source_references,
            key=lambda item: (
                item.chunk_id or "",
                item.path,
                item.start_line,
                item.end_line,
            ),
        )
        if reference.chunk_id
    )
    _table(lines, ("Evidence type", "Locator", "Identity"), rows)
    lines.extend(["", "### Persisted Tool Runs", ""])
    if tool_run_ids:
        _bullets(lines, tool_run_ids)
    else:
        lines.append("No persisted tool-run IDs were supplied.")
    lines.append("")


def _render_limitations(
    lines: list[str],
    report: StaticReportInput,
    missing: tuple[ReportSection, ...],
    tool_run_ids: tuple[str, ...],
) -> None:
    _heading(lines, "Limitations")
    limitations = [
        (
            "Static analysis cannot confirm runtime data flow, server behavior, "
            "certificate-pinning behavior, or practical exploitability."
        )
    ]
    if report.apk_metadata is not None:
        limitations.append(
            "APK signing evidence records fingerprints and parser observations only; "
            "signatures, certificate trust, signer identity, and APK integrity were "
            "not cryptographically verified."
        )
    if not report.project.authorization_confirmed:
        limitations.append("Authorization was not recorded in the report input.")
    missing_messages = {
        ReportSection.APK_METADATA: (
            "APK content and signing metadata was not supplied."
        ),
        ReportSection.JADX: "JADX decompilation output was not supplied.",
        ReportSection.MANIFEST: "Decoded manifest analysis was not supplied.",
        ReportSection.OBFUSCATION: "Obfuscation analysis was not supplied.",
        ReportSection.CONTEXT: "Context index metrics were not supplied.",
        ReportSection.SOURCE_EVIDENCE: "No source references were supplied.",
    }
    limitations.extend(missing_messages[section] for section in missing)
    if report.jadx is not None and report.jadx.status.value not in {
        "succeeded",
        "cached",
    }:
        limitations.append(
            f"JADX did not complete successfully ({report.jadx.status.value})."
        )
    if report.jadx is not None and report.jadx.options.deobfuscate:
        limitations.append(
            "JADX deobfuscation/renaming was enabled, so name-based obfuscation "
            "signals may differ from the original bytecode."
        )
    if report.obfuscation is not None and report.obfuscation.warnings:
        limitations.append(
            "The obfuscation assessment emitted coverage warnings and must not be "
            "treated as a complete classification."
        )
    if (
        report.context is not None
        and report.context.embedding_provider == "local-hashing-v1"
    ):
        limitations.append(
            "The local-hashing embedding provider is a deterministic lexical "
            "fallback, not a learned semantic model."
        )
    if report.source_references:
        limitations.append(
            "Retrieved source references are ranked candidates for review, not proof "
            "that the analysis goal or runtime data flow is established."
        )
    if not tool_run_ids:
        limitations.append("No persisted tool-run IDs were supplied for audit linkage.")
    limitations.extend(_sorted_unique(report.limitations))
    _bullets(lines, _unique(limitations))
    lines.append("")


def _tool_run_ids(report: StaticReportInput) -> tuple[str, ...]:
    values = list(report.tool_run_ids)
    values.extend(
        reference.tool_run_id
        for reference in report.source_references
        if reference.tool_run_id is not None
    )
    return _sorted_unique(values)


def _source_locator(reference: SourceReference) -> str:
    if reference.start_line == reference.end_line:
        return f"{reference.path}:{reference.start_line}"
    return f"{reference.path}:{reference.start_line}-{reference.end_line}"


def _content_entry_sort_key(entry: ContentEntry) -> tuple[object, ...]:
    return (
        entry.path.casefold(),
        entry.path,
        entry.sha256,
        entry.size_bytes,
        entry.compressed_size_bytes,
    )


def _signing_scheme_sort_key(
    scheme: SigningSchemeEvidence,
) -> tuple[object, ...]:
    return (
        scheme.scheme.value,
        scheme.block_id,
        not scheme.parsed,
        scheme.error or "",
    )


def _sdk_range(min_sdk: int | None, max_sdk: int | None) -> str:
    if min_sdk is None and max_sdk is None:
        return "Not supplied"
    minimum = str(min_sdk) if min_sdk is not None else "unspecified"
    maximum = str(max_sdk) if max_sdk is not None else "unbounded"
    return f"{minimum}-{maximum}"


def _apk_metadata_evidence_count(metadata: ApkMetadataResult) -> int:
    signing = metadata.signing
    count = (
        len(metadata.assets)
        + len(metadata.resources)
        + len(metadata.native_libraries)
        + len(metadata.dex_files)
        + len(signing.legacy_entries)
        + len(signing.unsupported_block_ids)
    )
    for scheme in signing.schemes:
        count += 1
        for signer in scheme.signers:
            count += 1 + len(signer.certificates) + len(signer.signatures)
    return count


def _reported_jadx_error_count(jadx: JadxResult) -> int | None:
    """Recover the aggregate count from legacy diagnostics when necessary."""

    if jadx.reported_error_count is not None:
        return jadx.reported_error_count
    counts = tuple(
        int(match.group("count"))
        for diagnostic in (*jadx.errors, *jadx.warnings)
        if (match := _JADX_ERROR_COUNT_PATTERN.search(diagnostic)) is not None
    )
    return max(counts) if counts else None


def _render_diagnostics(
    lines: list[str], warnings: tuple[str, ...], errors: tuple[str, ...]
) -> None:
    if warnings:
        lines.extend(["", "### Warnings", ""])
        _bullets(lines, _sorted_unique(warnings))
    if errors:
        lines.extend(["", "### Errors", ""])
        _bullets(lines, _sorted_unique(errors))


def _heading(lines: list[str], title: str) -> None:
    lines.extend([f"## {title}", ""])


def _table(
    lines: list[str],
    headers: tuple[str, ...],
    rows: Iterable[tuple[str, ...]],
) -> None:
    lines.append("| " + " | ".join(_inline(value) for value in headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        if len(row) != len(headers):
            raise StaticReportError("report table row has the wrong column count")
        lines.append("| " + " | ".join(_inline(value) for value in row) + " |")


def _table_or_empty(
    lines: list[str],
    headers: tuple[str, ...],
    rows: Iterable[tuple[str, ...]],
    empty_message: str,
) -> None:
    materialized = tuple(rows)
    if materialized:
        _table(lines, headers, materialized)
    else:
        lines.append(empty_message)


def _bullets(lines: list[str], values: Iterable[str]) -> None:
    lines.extend(f"- {_inline(value)}" for value in values)


def _inline(value: str) -> str:
    normalized = " ".join(value.split())
    escaped = html.escape(normalized, quote=False).replace("\\", "\\\\")
    for character in ("`", "*", "[", "]", "|", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped or "—"


def _yes_no(value: bool) -> str:
    return "Yes" if value else "No"


def _yes_no_unknown(value: bool | None) -> str:
    return "Unknown" if value is None else _yes_no(value)


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values), key=lambda item: (item.casefold(), item)))


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _coerce_model(value: object, model: type[BaseModel]) -> object:
    if value is None or isinstance(value, model):
        return value
    if not isinstance(value, Mapping):
        return value
    try:
        encoded = json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        )
    except (TypeError, ValueError):
        return value
    return model.model_validate_json(encoded)


def _json_default(value: Any) -> str:
    return str(value)
