from pathlib import Path

import pytest

from reverserx.tools.base import ToolContext
from reverserx.tools.static.manifest import (
    ComponentKind,
    ManifestAnalyzeInput,
    ManifestAnalyzeTool,
    ManifestError,
    analyze_manifest,
)

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.fixture"
    android:versionCode="42"
    android:versionName="1.2.3">
    <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-feature android:name="android.hardware.camera" />
    <application android:debuggable="true" android:allowBackup="false"
        android:usesCleartextTraffic="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name="SyncService" android:exported="true"
            android:permission="com.example.fixture.INTERNAL" />
        <receiver android:name=".Disabled" android:exported="true"
            android:enabled="false" />
        <provider android:name="com.example.fixture.DataProvider"
            android:authorities="com.example.fixture.data" android:exported="false" />
    </application>
</manifest>
"""


def _write_manifest(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MANIFEST, encoding="utf-8")
    return path


def test_manifest_analysis_returns_evidence_linked_attack_surface(
    tmp_path: Path,
) -> None:
    result = analyze_manifest(_write_manifest(tmp_path / "AndroidManifest.xml"))

    assert result.package_name == "com.example.fixture"
    assert result.version_code == "42"
    assert result.min_sdk == "28"
    assert result.target_sdk == "35"
    assert result.debuggable
    assert result.allow_backup is False
    assert result.uses_cleartext_traffic is True
    assert [permission.name for permission in result.permissions] == [
        "android.permission.CAMERA",
        "android.permission.INTERNET",
    ]
    assert result.permissions[0].dangerous
    assert result.features == ("android.hardware.camera",)
    assert len(result.components) == 4

    activity = next(
        item for item in result.components if item.kind is ComponentKind.ACTIVITY
    )
    assert activity.name == "com.example.fixture.MainActivity"
    assert activity.exported
    assert activity.exported_source == "explicit"
    assert activity.exported_source_locator == (
        "/manifest/application/activity[1]/@android:exported"
    )
    assert activity.source_locator == "/manifest/application/activity[1]"
    assert {entry.component for entry in result.attack_surface} == {
        "com.example.fixture.MainActivity",
        "com.example.fixture.SyncService",
    }


def test_manifest_tool_restricts_reads_to_runtime_data(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    inside = _write_manifest(
        data_dir / "projects" / "prj_fixture" / "AndroidManifest.xml"
    )
    other_project = _write_manifest(
        data_dir / "projects" / "prj_other" / "AndroidManifest.xml"
    )
    outside = _write_manifest(tmp_path / "outside.xml")
    tool = ManifestAnalyzeTool()
    context = ToolContext(project_id="prj_fixture", data_dir=data_dir)

    execution = tool.execute(context, ManifestAnalyzeInput(manifest_path=inside))
    assert execution.output["package_name"] == "com.example.fixture"

    with pytest.raises(ManifestError, match="must be within"):
        tool.execute(context, ManifestAnalyzeInput(manifest_path=outside))
    with pytest.raises(ManifestError, match="must be within"):
        tool.execute(context, ManifestAnalyzeInput(manifest_path=other_project))


def _component_manifest(
    kind: str,
    target_sdk: str,
    *,
    intent_filter: bool,
    exported: bool | None = None,
) -> str:
    exported_attribute = (
        "" if exported is None else f' android:exported="{str(exported).lower()}"'
    )
    target_attribute = (
        ' android:targetActivity=".Target"' if kind == "activity-alias" else ""
    )
    filter_xml = (
        '<intent-filter><action android:name="com.example.ACTION" /></intent-filter>'
        if intent_filter
        else ""
    )
    return f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.matrix">
    <uses-sdk android:minSdkVersion="1" android:targetSdkVersion="{target_sdk}" />
    <application>
        <{kind} android:name=".Component"{target_attribute}{exported_attribute}>
            {filter_xml}
        </{kind}>
    </application>
</manifest>"""


ANDROID_NS = "http://schemas.android.com/apk/res/android"


@pytest.mark.parametrize(
    (
        "kind",
        "target_sdk",
        "intent_filter",
        "explicit",
        "expected",
        "source",
        "violation",
    ),
    [
        ("activity", "30", True, None, True, "inferred-from-intent-filter", False),
        ("activity", "30", False, None, False, "inferred-no-intent-filter", False),
        ("service", "30", True, None, True, "inferred-from-intent-filter", False),
        ("receiver", "30", True, None, True, "inferred-from-intent-filter", False),
        (
            "activity-alias",
            "30",
            True,
            None,
            True,
            "inferred-from-intent-filter",
            False,
        ),
        (
            "provider",
            "16",
            True,
            None,
            True,
            "inferred-provider-target-sdk-16-or-lower",
            False,
        ),
        (
            "provider",
            "17",
            True,
            None,
            False,
            "inferred-provider-target-sdk-17-or-higher",
            False,
        ),
        (
            "activity",
            "31",
            True,
            None,
            None,
            "missing-required-explicit",
            True,
        ),
        (
            "service",
            "31",
            True,
            None,
            None,
            "missing-required-explicit",
            True,
        ),
        (
            "receiver",
            "31",
            True,
            None,
            None,
            "missing-required-explicit",
            True,
        ),
        (
            "activity-alias",
            "31",
            True,
            None,
            None,
            "missing-required-explicit",
            True,
        ),
        ("activity", "31", False, None, False, "inferred-no-intent-filter", False),
        ("service", "35", True, True, True, "explicit", False),
        ("provider", "16", False, False, False, "explicit", False),
    ],
)
def test_exported_semantics_follow_component_and_target_sdk_matrix(
    tmp_path: Path,
    kind: str,
    target_sdk: str,
    intent_filter: bool,
    explicit: bool | None,
    expected: bool | None,
    source: str,
    violation: bool,
) -> None:
    path = tmp_path / f"{kind}-{target_sdk}.xml"
    path.write_text(
        _component_manifest(
            kind, target_sdk, intent_filter=intent_filter, exported=explicit
        ),
        encoding="utf-8",
    )

    result = analyze_manifest(path)
    component = result.components[0]

    assert component.exported is expected
    assert component.exported_source == source
    assert component.exported_requirement_violation is violation
    if violation:
        assert component.name not in [
            entry.component for entry in result.attack_surface
        ]
        assert component.source_locator in result.warnings[0]
        assert "invalid as declared" in result.warnings[0]


def test_application_and_provider_permissions_are_effective_guards(
    tmp_path: Path,
) -> None:
    path = tmp_path / "permissions.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.permissions">
        <uses-sdk android:targetSdkVersion="35" />
        <application android:permission="com.example.APP">
            <activity android:name=".Inherited" android:exported="true" />
            <service android:name=".Override" android:exported="true"
                android:permission="com.example.SERVICE" />
            <provider android:name=".Provider" android:exported="true"
                android:authorities="com.example.provider"
                android:permission="com.example.PROVIDER"
                android:readPermission="com.example.READ" />
        </application>
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)
    by_kind = {component.kind: component for component in result.components}
    activity = by_kind[ComponentKind.ACTIVITY]
    service = by_kind[ComponentKind.SERVICE]
    provider = by_kind[ComponentKind.PROVIDER]

    assert result.application_permission == "com.example.APP"
    assert activity.declared_permission is None
    assert activity.permission == "com.example.APP"
    assert activity.permission_source == "application"
    assert activity.permission_source_locator == (
        "/manifest/application/@android:permission"
    )
    assert service.permission == "com.example.SERVICE"
    assert service.permission_source == "component"
    assert provider.permission == "com.example.PROVIDER"
    assert provider.read_permission == "com.example.READ"
    assert provider.read_permission_source == "provider-readPermission"
    assert provider.write_permission == "com.example.PROVIDER"
    assert provider.write_permission_source == "component"

    surface = {entry.kind: entry for entry in result.attack_surface}
    assert surface[ComponentKind.ACTIVITY].unguarded_operations == ()
    assert surface[ComponentKind.PROVIDER].unguarded_operations == ()
    assert surface[ComponentKind.PROVIDER].read_permission == "com.example.READ"
    assert surface[ComponentKind.PROVIDER].write_permission == "com.example.PROVIDER"
    assert "/manifest/application/provider[1]/@android:readPermission" in (
        surface[ComponentKind.PROVIDER].evidence_locators
    )


def test_provider_reports_only_the_unguarded_operation(tmp_path: Path) -> None:
    path = tmp_path / "provider.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.provider">
        <uses-sdk android:targetSdkVersion="35" />
        <application>
            <provider android:name=".Provider" android:exported="true"
                android:authorities="com.example.provider"
                android:readPermission="com.example.READ" />
        </application>
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)
    provider = result.components[0]
    surface = result.attack_surface[0]

    assert provider.read_permission == "com.example.READ"
    assert provider.write_permission is None
    assert surface.unguarded_operations == ("write",)
    assert surface.reason == "exported provider has no write permission guard"


def test_missing_target_sdk_inherits_min_sdk_for_provider_default(
    tmp_path: Path,
) -> None:
    path = tmp_path / "inherited-target.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.provider">
        <uses-sdk android:minSdkVersion="16" />
        <application>
            <provider android:name=".Provider"
                android:authorities="com.example.provider" />
        </application>
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)

    assert result.target_sdk is None
    assert result.effective_target_sdk == 16
    assert result.components[0].exported is True


def test_nonnumeric_target_sdk_keeps_dependent_export_state_unknown(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unknown-target.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.unknown">
        <uses-sdk android:targetSdkVersion="FuturePreview" />
        <application>
            <provider android:name=".Provider"
                android:authorities="com.example.provider" />
        </application>
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)

    assert result.effective_target_sdk is None
    assert result.components[0].exported is None
    assert result.components[0].exported_source == "indeterminate-target-sdk"
    assert any("numeric API level" in warning for warning in result.warnings)


def test_nonliteral_booleans_are_reported_as_potential_attack_surface(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resource-booleans.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.resources">
        <uses-sdk android:targetSdkVersion="35" />
        <application android:enabled="@bool/app_enabled"
            android:debuggable="@bool/debuggable"
            android:allowBackup="@bool/allow_backup"
            android:usesCleartextTraffic="@bool/cleartext">
            <activity android:name=".Potential"
                android:exported="@bool/exported"
                android:enabled="@bool/component_enabled" />
        </application>
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)
    component = result.components[0]

    assert component.exported is None
    assert component.exported_source == "indeterminate-nonliteral"
    assert component.enabled is None
    assert component.enabled_source == "indeterminate-application-enabled"
    assert result.debuggable is True
    assert result.allow_backup is None
    assert result.uses_cleartext_traffic is None
    assert result.attack_surface[0].component == component.name
    assert "potential attack surface" in result.attack_surface[0].reason
    assert "export state is indeterminate" in result.attack_surface[0].reason
    assert any("@android:exported" in warning for warning in result.warnings)
    assert any("@android:enabled" in warning for warning in result.warnings)
    assert any("@android:debuggable" in warning for warning in result.warnings)
    assert any(
        "treated conservatively as true" in warning for warning in result.warnings
    )


def test_sdk_23_and_modern_dangerous_permissions_are_inventoried(
    tmp_path: Path,
) -> None:
    path = tmp_path / "permissions-sdk-23.xml"
    path.write_text(
        f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.permissions">
        <uses-permission-sdk-23 android:name="android.permission.CAMERA" />
        <uses-permission android:name="android.permission.BLUETOOTH_SCAN" />
        <uses-permission android:name="android.permission.NEARBY_WIFI_DEVICES" />
        <application />
    </manifest>""",
        encoding="utf-8",
    )

    result = analyze_manifest(path)
    by_name = {permission.name: permission for permission in result.permissions}

    assert by_name["android.permission.CAMERA"].dangerous
    assert by_name["android.permission.CAMERA"].source_locator == (
        "/manifest/uses-permission-sdk-23[1]"
    )
    assert by_name["android.permission.BLUETOOTH_SCAN"].dangerous
    assert by_name["android.permission.NEARBY_WIFI_DEVICES"].dangerous


@pytest.mark.parametrize(
    "content, message",
    [
        ("not XML", "invalid decoded manifest"),
        ("<root />", "root element"),
        (
            '<!DOCTYPE manifest [<!ENTITY x "x">]><manifest package="x"/>',
            "DTD",
        ),
        (
            " " * 3000
            + '<!DOCTYPE manifest [<!ENTITY x "x">]><manifest package="&x;"/>',
            "DTD",
        ),
        ("<manifest />", "package name"),
    ],
)
def test_manifest_rejects_invalid_or_unsafe_input(
    tmp_path: Path, content: str, message: str
) -> None:
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ManifestError, match=message):
        analyze_manifest(path)
