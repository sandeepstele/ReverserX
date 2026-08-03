from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from reverserx.reporting.static import (
    ContextReportSummary,
    ReportProject,
    ReportSection,
    SourceReference,
    StaticReportError,
    StaticReportInput,
    StaticReportTool,
    render_static_report,
)
from reverserx.tools.base import ToolContext
from reverserx.tools.static.apk import (
    ApkDescriptor,
    ApkInspectionResult,
    ApkRole,
    PackageSourceKind,
)
from reverserx.tools.static.jadx import JadxOptions, JadxResult, JadxStatus
from reverserx.tools.static.manifest import (
    AttackSurfaceEntry,
    ComponentKind,
    ManifestAnalysis,
    PermissionUse,
)
from reverserx.tools.static.metadata import (
    ApkMetadataResult,
    CertificateEvidence,
    ContentEntry,
    NativeLibraryEntry,
    SignatureEvidenceStatus,
    SignatureRecordEvidence,
    SignerEvidence,
    SigningEvidence,
    SigningScheme,
    SigningSchemeEvidence,
)
from reverserx.tools.static.obfuscation import (
    ObfuscationKind,
    ObfuscationReport,
    ObfuscationSignal,
)

APK_SHA = "a" * 64
SPLIT_A_SHA = "b" * 64
SPLIT_Z_SHA = "c" * 64
CACHE_KEY = "d" * 64
ASSET_SHA = "e" * 64
RESOURCE_SHA = "f" * 64
NATIVE_SHA = "1" * 64
DEX_SHA = "2" * 64
CERTIFICATE_SHA = "3" * 64
SIGNATURE_SHA = "4" * 64
PUBLIC_KEY_SHA = "5" * 64


def _apk_result(*, reverse_splits: bool = False) -> ApkInspectionResult:
    splits: tuple[ApkDescriptor, ...] = (
        ApkDescriptor(
            name="split-z.apk",
            sha256=SPLIT_Z_SHA,
            size_bytes=30,
            role=ApkRole.SPLIT,
            split_id="config.z",
            manifest_present=True,
            dex_files=(),
            archive_entry_count=2,
            uncompressed_size_bytes=35,
        ),
        ApkDescriptor(
            name="split-a.apk",
            sha256=SPLIT_A_SHA,
            size_bytes=20,
            role=ApkRole.SPLIT,
            split_id="config.a",
            manifest_present=True,
            dex_files=(),
            archive_entry_count=2,
            uncompressed_size_bytes=25,
        ),
    )
    if not reverse_splits:
        splits = tuple(reversed(splits))
    return ApkInspectionResult(
        source_path="/fixtures/application.apkm",
        source_kind=PackageSourceKind.APKM_ARCHIVE,
        source_sha256=APK_SHA,
        source_size_bytes=1_024,
        base_apk=ApkDescriptor(
            name="base.apk",
            sha256=APK_SHA,
            size_bytes=900,
            role=ApkRole.BASE,
            manifest_present=True,
            dex_files=("classes.dex", "classes2.dex"),
            archive_entry_count=8,
            uncompressed_size_bytes=1_800,
        ),
        split_apks=splits,
    )


def _jadx_result() -> JadxResult:
    output_dir = Path("/runtime/projects/prj_fixture/jadx/output")
    return JadxResult(
        status=JadxStatus.CACHED,
        cache_hit=True,
        apk_path=Path("/runtime/artifacts/base.apk"),
        apk_sha256=APK_SHA,
        output_dir=output_dir,
        cache_key=CACHE_KEY,
        cache_marker_path=output_dir / ".reverserx-jadx-cache.json",
        jadx_version="1.5.6",
        options=JadxOptions(
            threads=4,
            deobfuscate=True,
            show_inconsistent_code=False,
            decode_resources=True,
        ),
        version_command=("jadx", "--version"),
        command=("jadx", "-d", str(output_dir), "/runtime/artifacts/base.apk"),
        version_probe_duration_seconds=0.01,
        duration_seconds=0.0,
        return_code=0,
        source_file_count=120,
        resource_file_count=45,
        manifest_path=output_dir / "resources" / "AndroidManifest.xml",
        stdout="",
        stderr="",
        stdout_truncated=False,
        stderr_truncated=False,
        warnings=("Recovered one inconsistent class",),
    )


def _partial_jadx_result() -> JadxResult:
    return _jadx_result().model_copy(
        update={
            "status": JadxStatus.PARTIAL,
            "return_code": 3,
            "reported_error_count": 1_095,
            "warnings": (
                "JADX returned errors; partial output was accepted by explicit request",
            ),
            "errors": ("ERROR - finished with errors, count: 1095",),
        }
    )


def _metadata_result(
    *, reverse_entries: bool = False, escaped_values: bool = False
) -> ApkMetadataResult:
    asset_paths = (
        "assets/zeta|<script>.json" if escaped_values else "assets/zeta.json",
        "assets/alpha\n# heading.json" if escaped_values else "assets/alpha.json",
    )
    assets: tuple[ContentEntry, ...] = tuple(
        ContentEntry(
            path=path,
            size_bytes=index + 10,
            compressed_size_bytes=index + 5,
            sha256=ASSET_SHA,
        )
        for index, path in enumerate(asset_paths)
    )
    resources = (
        ContentEntry(
            path="res/xml/network_security_config.xml",
            size_bytes=30,
            compressed_size_bytes=20,
            sha256=RESOURCE_SHA,
        ),
    )
    dex_files: tuple[ContentEntry, ...] = (
        ContentEntry(
            path="classes.dex",
            size_bytes=200,
            compressed_size_bytes=150,
            sha256=DEX_SHA,
        ),
        ContentEntry(
            path="classes2.dex",
            size_bytes=100,
            compressed_size_bytes=80,
            sha256=APK_SHA,
        ),
    )
    if reverse_entries:
        assets = tuple(reversed(assets))
        dex_files = tuple(reversed(dex_files))
    warnings: tuple[str, ...] = (
        "Zulu | <script> warning"
        if escaped_values
        else "Ignored one nonstandard lib entry.",
        "Alpha\n# fake warning"
        if escaped_values
        else "Inventory hashes are observational evidence.",
    )
    if reverse_entries:
        warnings = tuple(reversed(warnings))
    return ApkMetadataResult(
        source_path=(
            "/runtime/artifacts/base|<script>.apk"
            if escaped_values
            else "/runtime/artifacts/base.apk"
        ),
        apk_sha256=APK_SHA,
        apk_size_bytes=900,
        archive_entry_count=12,
        categorized_entry_count=6,
        assets=assets,
        resources=resources,
        native_libraries=(
            NativeLibraryEntry(
                path="lib/arm64-v8a/libfixture.so",
                size_bytes=400,
                compressed_size_bytes=350,
                sha256=NATIVE_SHA,
                abi="arm64-v8a",
                library_name="libfixture.so",
            ),
        ),
        dex_files=dex_files,
        signing=SigningEvidence(
            status=SignatureEvidenceStatus.RECOGNIZED_SCHEME,
            signing_block_present=True,
            schemes=(
                SigningSchemeEvidence(
                    scheme=SigningScheme.V2,
                    block_id=0x7109871A,
                    parsed=True,
                    signers=(
                        SignerEvidence(
                            signer_index=0,
                            certificates=(
                                CertificateEvidence(
                                    certificate_index=0,
                                    der_sha256=CERTIFICATE_SHA,
                                    size_bytes=128,
                                    der_sequence_valid=True,
                                ),
                            ),
                            signatures=(
                                SignatureRecordEvidence(
                                    signature_index=0,
                                    algorithm_id=0x0103,
                                    signature_sha256=SIGNATURE_SHA,
                                    size_bytes=64,
                                ),
                            ),
                            public_key_sha256=PUBLIC_KEY_SHA,
                            public_key_size_bytes=91,
                        ),
                    ),
                ),
            ),
            warnings=(
                "Signing bytes were fingerprinted but not cryptographically verified.",
            ),
        ),
        warnings=warnings,
    )


def _manifest_result() -> ManifestAnalysis:
    return ManifestAnalysis(
        manifest_path="/runtime/output/resources/AndroidManifest.xml",
        package_name="com.example.fixture",
        version_name="1.2.3",
        version_code="42",
        min_sdk="28",
        target_sdk="35",
        debuggable=False,
        allow_backup=False,
        uses_cleartext_traffic=True,
        permissions=(
            PermissionUse(
                name="android.permission.INTERNET",
                dangerous=False,
                source_locator="/manifest/uses-permission[2]",
            ),
            PermissionUse(
                name="android.permission.CAMERA",
                dangerous=True,
                source_locator="/manifest/uses-permission[1]",
            ),
        ),
        attack_surface=(
            AttackSurfaceEntry(
                component="com.example.fixture.MainActivity",
                kind=ComponentKind.ACTIVITY,
                permission=None,
                reason="exported component has no permission guard",
                source_locator="/manifest/application/activity[1]",
            ),
        ),
    )


def _obfuscation_result() -> ObfuscationReport:
    return ObfuscationReport(
        source_root="/runtime/output/sources",
        kind=ObfuscationKind.NAME,
        confidence=0.8,
        likely_products=("ExampleShield",),
        file_count=120,
        class_count=80,
        method_count=400,
        short_name_ratio=0.75,
        identifier_entropy=4.1234,
        signals=(
            ObfuscationSignal(
                name="short-identifiers",
                score=0.8,
                evidence="300 of 400 identifiers have length <= 2",
                locators=("a/a.java",),
            ),
        ),
        warnings=("file limit reached at 100",),
    )


def _complete_input(
    *,
    project: ReportProject | None = None,
    references: tuple[SourceReference, ...] | None = None,
    tool_run_ids: tuple[str, ...] = ("run_manifest", "run_jadx"),
    limitations: tuple[str, ...] = ("A custom loader was not evaluated.",),
    reverse_splits: bool = False,
    apk_metadata: ApkMetadataResult | None = None,
) -> StaticReportInput:
    return StaticReportInput(
        project=project
        or ReportProject(
            project_id="prj_fixture",
            name="Fixture App",
            slug="fixture-app",
            description="Authorized internal fixture",
            analysis_goal="Locate request encryption",
            authorization_confirmed=True,
            authorized_scope=("api.example.test", "com.example.fixture"),
        ),
        apk=_apk_result(reverse_splits=reverse_splits),
        apk_metadata=apk_metadata or _metadata_result(),
        jadx=_jadx_result(),
        manifest=_manifest_result(),
        obfuscation=_obfuscation_result(),
        context=ContextReportSummary(
            index_id="idx_fixture",
            source_root="/runtime/output/sources",
            source_file_count=120,
            skipped_source_file_count=0,
            oversized_fallback_source_file_count=1,
            source_index_warning_count=1,
            source_index_warnings=(
                "Large.java (oversized_fallback): indexed as bounded windows",
            ),
            chunk_count=450,
            summary_count=90,
            vector_document_count=450,
            embedding_provider="local-hashing-v1",
            project_summary="The application signs outbound requests.",
        ),
        source_references=references
        or (
            SourceReference(
                path="com/example/Crypto.java",
                start_line=20,
                end_line=35,
                symbol="Crypto.sign",
                summary="Signs the serialized request body.",
                chunk_id="chk_crypto",
                tool_run_id="run_query",
            ),
        ),
        tool_run_ids=tool_run_ids,
        limitations=limitations,
    )


def test_complete_report_contains_findings_evidence_and_provenance() -> None:
    rendered = render_static_report(_complete_input())
    markdown = rendered.markdown

    assert "authorized static analysis only" in markdown
    assert "## Package Inventory" in markdown
    assert "## APK Static Metadata" in markdown
    assert "recognized_scheme" in markdown
    assert "arm64-v8a" in markdown
    assert ASSET_SHA in markdown
    assert RESOURCE_SHA in markdown
    assert NATIVE_SHA in markdown
    assert DEX_SHA in markdown
    assert CERTIFICATE_SHA in markdown
    assert SIGNATURE_SHA in markdown
    assert PUBLIC_KEY_SHA in markdown
    assert "does not cryptographically verify signatures" in markdown
    assert "## Decompilation" in markdown
    assert "## Manifest Analysis" in markdown
    assert "android.permission.CAMERA" in markdown
    assert "com.example.fixture.MainActivity" in markdown
    assert "## Obfuscation Assessment" in markdown
    assert "80.0%" in markdown
    assert "## Context Index" in markdown
    assert "| Source files indexed | 120 |" in markdown
    assert "| Oversized source fallbacks | 1 |" in markdown
    assert "Large.java (oversized_fallback): indexed as bounded windows" in markdown
    assert "com/example/Crypto.java:20-35" in markdown
    assert "## Evidence and Provenance" in markdown
    assert APK_SHA in markdown
    assert CACHE_KEY in markdown
    assert "run_query" in markdown
    assert "## Limitations" in markdown
    assert "A custom loader was not evaluated." in markdown
    assert "name-based obfuscation signals may differ" in markdown
    assert "obfuscation assessment emitted coverage warnings" in markdown
    assert "not a learned semantic model" in markdown
    assert "ranked candidates for review" in markdown
    assert rendered.missing_sections == ()
    assert rendered.included_sections == tuple(ReportSection)
    assert rendered.evidence_reference_count == 18
    assert rendered.tool_run_count == 3
    assert rendered.markdown_sha256 == hashlib.sha256(markdown.encode()).hexdigest()


def test_partial_jadx_outcome_is_explicit_in_report_and_provenance() -> None:
    report = _complete_input().model_copy(update={"jadx": _partial_jadx_result()})

    rendered = render_static_report(report)
    markdown = rendered.markdown

    assert "| Status | partial |" in markdown
    assert "| Cache hit | Yes |" in markdown
    assert "| Return code | 3 |" in markdown
    assert "| Reported decompilation errors | 1095 |" in markdown
    assert "status=partial; return_code=3; cache_hit=Yes" in markdown
    assert "JADX reported error count" in markdown
    assert "JADX warning" in markdown
    assert "partial output was accepted by explicit request" in markdown
    assert "JADX error" in markdown
    assert "ERROR - finished with errors, count: 1095" in markdown
    assert "JADX did not complete successfully (partial)." in markdown


def test_legacy_partial_jadx_diagnostic_recovers_reported_error_count() -> None:
    legacy = _partial_jadx_result().model_copy(update={"reported_error_count": None})
    report = _complete_input().model_copy(update={"jadx": legacy})

    markdown = render_static_report(report).markdown

    assert "| Reported decompilation errors | 1095 |" in markdown
    assert "JADX reported error count" in markdown


def test_partial_report_is_explicit_about_missing_analysis() -> None:
    report = StaticReportInput(
        project=ReportProject(
            project_id="prj_fixture",
            name="Partial Fixture",
            authorization_confirmed=False,
        ),
        apk=_apk_result(),
    )

    rendered = render_static_report(report)

    assert rendered.included_sections == (
        ReportSection.PROJECT,
        ReportSection.PACKAGE,
        ReportSection.PROVENANCE,
        ReportSection.LIMITATIONS,
    )
    assert rendered.missing_sections == (
        ReportSection.APK_METADATA,
        ReportSection.JADX,
        ReportSection.MANIFEST,
        ReportSection.OBFUSCATION,
        ReportSection.CONTEXT,
        ReportSection.SOURCE_EVIDENCE,
    )
    assert "JADX decompilation output was not supplied." in rendered.markdown
    assert "APK content and signing metadata was not supplied." in rendered.markdown
    assert "Authorization was not recorded" in rendered.markdown
    assert "No persisted tool-run IDs" in rendered.markdown
    assert "## Manifest Analysis" not in rendered.markdown


def test_markdown_escaping_and_order_are_stable() -> None:
    project_a = ReportProject(
        project_id="prj_fixture",
        name="App | <script>\n# injected",
        authorization_confirmed=True,
        authorized_scope=("zeta|scope", "alpha\n# heading"),
    )
    project_b = project_a.model_copy(
        update={"authorized_scope": tuple(reversed(project_a.authorized_scope))}
    )
    references = (
        SourceReference(
            path="z/File.java",
            start_line=9,
            end_line=9,
            summary="Uses | token\n## fake heading",
            chunk_id="chunk-z",
        ),
        SourceReference(
            path="a/File.java",
            start_line=2,
            end_line=4,
            summary="First `reference`",
            chunk_id="chunk-a",
        ),
    )
    first = _complete_input(
        project=project_a,
        references=references,
        tool_run_ids=("run-z", "run-a"),
        limitations=("Zulu | limit", "Alpha\n# limit"),
        reverse_splits=True,
        apk_metadata=_metadata_result(
            reverse_entries=True,
            escaped_values=True,
        ),
    )
    second = _complete_input(
        project=project_b,
        references=tuple(reversed(references)),
        tool_run_ids=("run-a", "run-z"),
        limitations=("Alpha\n# limit", "Zulu | limit"),
        reverse_splits=False,
        apk_metadata=_metadata_result(escaped_values=True),
    )

    first_render = render_static_report(first)
    second_render = render_static_report(second)

    assert first_render.markdown == second_render.markdown
    assert first_render.markdown_sha256 == second_render.markdown_sha256
    assert "<script>" not in first_render.markdown
    assert "&lt;script&gt;" in first_render.markdown
    assert "\\|" in first_render.markdown
    assert "\n# injected" not in first_render.markdown
    assert "\n## fake heading" not in first_render.markdown
    assert "assets/zeta\\|&lt;script&gt;.json" in first_render.markdown
    assert "\n# fake warning" not in first_render.markdown
    assert first_render.markdown.index("split-a.apk") < first_render.markdown.index(
        "split-z.apk"
    )
    assert first_render.markdown.index("run-a") < first_render.markdown.index("run-z")


def test_metadata_without_recognized_signing_evidence_is_conservative() -> None:
    metadata = _metadata_result().model_copy(
        update={
            "signing": SigningEvidence(
                status=SignatureEvidenceStatus.NO_RECOGNIZED_EVIDENCE,
                signing_block_present=False,
                warnings=(
                    "No recognized signature evidence was found; this does not "
                    "establish that the APK is unsigned.",
                ),
            )
        }
    )
    report = StaticReportInput(
        project=ReportProject(
            project_id="prj_fixture",
            name="Metadata-only Fixture",
            authorization_confirmed=True,
        ),
        apk=_apk_result(),
        apk_metadata=metadata,
    )

    rendered = render_static_report(report)

    assert ReportSection.APK_METADATA in rendered.included_sections
    assert ReportSection.APK_METADATA not in rendered.missing_sections
    assert "no_recognized_evidence" in rendered.markdown
    assert "does not establish that the APK is unsigned" in rendered.markdown
    assert "not cryptographically verified" in rendered.markdown
    assert "## Decompilation" not in rendered.markdown


def test_large_asset_inventory_is_deterministically_bounded() -> None:
    assets = tuple(
        ContentEntry(
            path=f"assets/{index:03d}.bin",
            size_bytes=index,
            compressed_size_bytes=index,
            sha256=f"{index:064x}",
        )
        for index in reversed(range(251))
    )
    metadata = _metadata_result().model_copy(
        update={
            "assets": assets,
            "categorized_entry_count": len(assets) + 4,
        }
    )

    rendered = render_static_report(
        StaticReportInput(
            project=ReportProject(
                project_id="prj_fixture",
                name="Large Inventory Fixture",
                authorization_confirmed=True,
            ),
            apk=_apk_result(),
            apk_metadata=metadata,
        )
    )

    assert "Total entries: 251; shown: 250." in rendered.markdown
    assert "assets/000.bin" in rendered.markdown
    assert "assets/249.bin" in rendered.markdown
    assert "assets/250.bin" not in rendered.markdown
    assert "complete inventory remains in the persisted apk_metadata tool output" in (
        rendered.markdown
    )


def test_json_like_tool_outputs_are_accepted_and_api_is_strict() -> None:
    original = _complete_input()
    serialized = original.model_dump(mode="json")

    restored = StaticReportInput.model_validate(serialized)

    assert render_static_report(restored) == render_static_report(original)
    with pytest.raises(ValidationError):
        StaticReportInput.model_validate({**serialized, "unexpected": True})
    with pytest.raises(ValidationError, match="end_line"):
        SourceReference(
            path="a.java",
            start_line=10,
            end_line=2,
            summary="invalid range",
        )
    mismatched_metadata = _metadata_result().model_copy(update={"apk_sha256": "9" * 64})
    with pytest.raises(ValidationError, match="does not match the base APK"):
        StaticReportInput(
            project=original.project,
            apk=original.apk,
            apk_metadata=mismatched_metadata,
        )


def test_tool_adapter_checks_project_context() -> None:
    report = _complete_input()
    tool = StaticReportTool()

    execution = tool.execute(
        ToolContext(project_id="prj_fixture", data_dir=Path("/runtime")), report
    )

    assert (
        execution.output["markdown_sha256"]
        == render_static_report(report).markdown_sha256
    )
    with pytest.raises(StaticReportError, match="does not match"):
        tool.execute(
            ToolContext(project_id="prj_other", data_dir=Path("/runtime")), report
        )
