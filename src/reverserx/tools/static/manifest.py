"""Deterministic analysis of JADX-decoded Android manifests."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_PROJECT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_ANDROID_12_TARGET_SDK = 31
_PROVIDER_PRIVATE_BY_DEFAULT_TARGET_SDK = 17

DANGEROUS_PERMISSIONS = frozenset(
    {
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.ACCEPT_HANDOVER",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_SENSORS_BACKGROUND",
        "android.permission.CALL_PHONE",
        "android.permission.CAMERA",
        "android.permission.GET_ACCOUNTS",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECORD_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.USE_SIP",
        "android.permission.UWB_RANGING",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.WRITE_CALENDAR",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.WRITE_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }
)


class ManifestError(ValueError):
    """Raised when decoded manifest input is invalid or unsafe."""


class ComponentKind(StrEnum):
    ACTIVITY = "activity"
    ACTIVITY_ALIAS = "activity-alias"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class IntentFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    data: tuple[dict[str, str], ...] = ()


class ManifestComponent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ComponentKind
    name: str
    exported: bool | None
    exported_source: str
    enabled: bool | None
    permission: str | None = None
    authorities: str | None = None
    intent_filters: tuple[IntentFilter, ...] = ()
    source_locator: str
    exported_source_locator: str | None = None
    exported_requirement_violation: bool = False
    declared_enabled: bool | None = None
    enabled_source: str = "component-or-default"
    declared_permission: str | None = None
    permission_source: str = "none"
    permission_source_locator: str | None = None
    read_permission: str | None = None
    read_permission_source: str | None = None
    read_permission_source_locator: str | None = None
    write_permission: str | None = None
    write_permission_source: str | None = None
    write_permission_source_locator: str | None = None


class PermissionUse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    dangerous: bool
    max_sdk: int | None = None
    source_locator: str


class AttackSurfaceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    component: str
    kind: ComponentKind
    permission: str | None
    reason: str
    source_locator: str
    read_permission: str | None = None
    write_permission: str | None = None
    unguarded_operations: tuple[str, ...] = ()
    evidence_locators: tuple[str, ...] = ()


class ManifestAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.1"
    manifest_path: str
    package_name: str
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    effective_target_sdk: int | None = None
    debuggable: bool = False
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    application_permission: str | None = None
    application_permission_source_locator: str | None = None
    permissions: tuple[PermissionUse, ...] = ()
    features: tuple[str, ...] = ()
    components: tuple[ManifestComponent, ...] = ()
    attack_surface: tuple[AttackSurfaceEntry, ...] = ()
    warnings: tuple[str, ...] = ()


class ManifestAnalyzeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_path: Path


class ManifestAnalyzeTool(BaseTool[ManifestAnalyzeInput]):
    name = "manifest_analyze"
    description = "Analyze a decoded AndroidManifest.xml with evidence locators."
    version = "1.1.0"
    input_model = ManifestAnalyzeInput

    def execute(
        self, context: ToolContext, arguments: ManifestAnalyzeInput
    ) -> ToolExecution:
        path = arguments.manifest_path.expanduser().resolve(strict=True)
        project_root = _project_root(context)
        _require_within(path, project_root)
        result = analyze_manifest(path)
        return ToolExecution(output=result.model_dump(mode="json"))


def analyze_manifest(path: Path) -> ManifestAnalysis:
    """Parse a text XML manifest produced by JADX or another trusted decoder."""

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    if len(raw) > 10_000_000:
        raise ManifestError("manifest exceeds the 10 MB safety limit")
    normalized = raw.upper()
    if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
        raise ManifestError("DTD and entity declarations are not allowed")
    if b"\x00" in raw[:128]:
        raise ManifestError("binary Android manifests must be decoded before analysis")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ManifestError(f"invalid decoded manifest XML: {exc}") from exc
    if _local_name(root.tag) != "manifest":
        raise ManifestError("manifest root element is missing")

    package_name = root.attrib.get("package", "").strip()
    if not package_name:
        raise ManifestError("manifest package name is missing")

    uses_sdk = root.find("uses-sdk")
    application = root.find("application")
    warnings: list[str] = []
    if application is None:
        warnings.append("manifest has no application element")

    permissions = tuple(
        sorted(
            (
                _permission(element, index, element_name)
                for element_name in ("uses-permission", "uses-permission-sdk-23")
                for index, element in enumerate(root.findall(element_name), 1)
            ),
            key=lambda item: (item.name, item.source_locator),
        )
    )
    features = tuple(
        sorted(
            {
                name
                for element in root.findall("uses-feature")
                if (name := _android_attr(element, "name"))
            }
        )
    )

    min_sdk = _android_attr(uses_sdk, "minSdkVersion")
    target_sdk = _android_attr(uses_sdk, "targetSdkVersion")
    effective_target_sdk = _effective_target_sdk(min_sdk, target_sdk, warnings)
    application_permission = _android_attr(application, "permission")
    application_permission_locator = (
        "/manifest/application/@android:permission"
        if application_permission is not None
        else None
    )
    application_enabled_raw = _android_attr(application, "enabled")
    application_enabled = (
        True
        if application_enabled_raw is None
        else _optional_bool_attr(
            application,
            "enabled",
            warnings=warnings,
            source_locator="/manifest/application/@android:enabled",
        )
    )

    components: list[ManifestComponent] = []
    if application is not None:
        for kind in ComponentKind:
            for index, element in enumerate(application.findall(kind.value), 1):
                components.append(
                    _component(
                        element,
                        kind,
                        index,
                        package_name,
                        effective_target_sdk,
                        application_permission,
                        application_permission_locator,
                        application_enabled,
                        warnings,
                    )
                )
    components.sort(key=lambda item: (item.kind.value, item.name))
    attack_surface = tuple(
        _attack_surface_entry(component)
        for component in components
        if _is_attack_surface_candidate(component)
    )

    return ManifestAnalysis(
        manifest_path=str(path),
        package_name=package_name,
        version_name=_android_attr(root, "versionName"),
        version_code=_android_attr(root, "versionCode"),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        effective_target_sdk=effective_target_sdk,
        debuggable=_bool_attr(
            application,
            "debuggable",
            False,
            warnings=warnings,
            source_locator="/manifest/application/@android:debuggable",
            unresolved_default=True,
        ),
        allow_backup=_optional_bool_attr(
            application,
            "allowBackup",
            warnings=warnings,
            source_locator="/manifest/application/@android:allowBackup",
        ),
        uses_cleartext_traffic=_optional_bool_attr(
            application,
            "usesCleartextTraffic",
            warnings=warnings,
            source_locator="/manifest/application/@android:usesCleartextTraffic",
        ),
        application_permission=application_permission,
        application_permission_source_locator=application_permission_locator,
        permissions=permissions,
        features=features,
        components=tuple(components),
        attack_surface=attack_surface,
        warnings=tuple(warnings),
    )


def _permission(element: ET.Element, index: int, element_name: str) -> PermissionUse:
    name = _android_attr(element, "name") or "<unnamed>"
    max_sdk_raw = _android_attr(element, "maxSdkVersion")
    try:
        max_sdk = int(max_sdk_raw) if max_sdk_raw else None
    except ValueError:
        max_sdk = None
    return PermissionUse(
        name=name,
        dangerous=name in DANGEROUS_PERMISSIONS,
        max_sdk=max_sdk,
        source_locator=f"/manifest/{element_name}[{index}]",
    )


def _component(
    element: ET.Element,
    kind: ComponentKind,
    index: int,
    package_name: str,
    effective_target_sdk: int | None,
    application_permission: str | None,
    application_permission_locator: str | None,
    application_enabled: bool | None,
    warnings: list[str],
) -> ManifestComponent:
    source_locator = f"/manifest/application/{kind.value}[{index}]"
    raw_name = _android_attr(element, "name") or "<unnamed>"
    name = _qualify_component(raw_name, package_name)
    intent_filters = tuple(
        _intent_filter(filter_element)
        for filter_element in element.findall("intent-filter")
    )
    explicit_exported_raw = _android_attr(element, "exported")
    explicit_exported = _optional_bool_attr(
        element,
        "exported",
        warnings=warnings,
        source_locator=f"{source_locator}/@android:exported",
    )
    (
        exported,
        exported_source,
        exported_source_locator,
        exported_requirement_violation,
    ) = _exported_state(
        kind,
        explicit_exported,
        explicit_exported_raw is not None,
        bool(intent_filters),
        effective_target_sdk,
        source_locator,
        warnings,
    )
    declared_permission = _android_attr(element, "permission")
    permission_source_locator: str | None
    if declared_permission is not None:
        permission = declared_permission
        permission_source = "component"
        permission_source_locator = f"{source_locator}/@android:permission"
    elif application_permission is not None:
        permission = application_permission
        permission_source = "application"
        permission_source_locator = application_permission_locator
    else:
        permission = None
        permission_source = "none"
        permission_source_locator = None

    read_permission: str | None = None
    read_permission_source: str | None = None
    read_permission_source_locator: str | None = None
    write_permission: str | None = None
    write_permission_source: str | None = None
    write_permission_source_locator: str | None = None
    if kind is ComponentKind.PROVIDER:
        declared_read_permission = _android_attr(element, "readPermission")
        declared_write_permission = _android_attr(element, "writePermission")
        if declared_read_permission is not None:
            read_permission = declared_read_permission
            read_permission_source = "provider-readPermission"
            read_permission_source_locator = f"{source_locator}/@android:readPermission"
        else:
            read_permission = permission
            read_permission_source = permission_source
            read_permission_source_locator = permission_source_locator
        if declared_write_permission is not None:
            write_permission = declared_write_permission
            write_permission_source = "provider-writePermission"
            write_permission_source_locator = (
                f"{source_locator}/@android:writePermission"
            )
        else:
            write_permission = permission
            write_permission_source = permission_source
            write_permission_source_locator = permission_source_locator

    declared_enabled_raw = _android_attr(element, "enabled")
    declared_enabled = _optional_bool_attr(
        element,
        "enabled",
        warnings=warnings,
        source_locator=f"{source_locator}/@android:enabled",
    )
    component_enabled = True if declared_enabled_raw is None else declared_enabled
    enabled = _effective_enabled(application_enabled, component_enabled)
    if application_enabled is False:
        enabled_source = "application-disabled"
    elif component_enabled is False:
        enabled_source = "component"
    elif application_enabled is None:
        enabled_source = "indeterminate-application-enabled"
    elif component_enabled is None:
        enabled_source = "indeterminate-component-enabled"
    elif declared_enabled_raw is not None:
        enabled_source = "component"
    else:
        enabled_source = "default-true"
    return ManifestComponent(
        kind=kind,
        name=name,
        exported=exported,
        exported_source=exported_source,
        exported_source_locator=exported_source_locator,
        exported_requirement_violation=exported_requirement_violation,
        enabled=enabled,
        declared_enabled=declared_enabled,
        enabled_source=enabled_source,
        declared_permission=declared_permission,
        permission=permission,
        permission_source=permission_source,
        permission_source_locator=permission_source_locator,
        read_permission=read_permission,
        read_permission_source=read_permission_source,
        read_permission_source_locator=read_permission_source_locator,
        write_permission=write_permission,
        write_permission_source=write_permission_source,
        write_permission_source_locator=write_permission_source_locator,
        authorities=_android_attr(element, "authorities"),
        intent_filters=intent_filters,
        source_locator=source_locator,
    )


def _intent_filter(element: ET.Element) -> IntentFilter:
    actions = tuple(
        sorted(
            name
            for child in element.findall("action")
            if (name := _android_attr(child, "name"))
        )
    )
    categories = tuple(
        sorted(
            name
            for child in element.findall("category")
            if (name := _android_attr(child, "name"))
        )
    )
    data: list[dict[str, str]] = []
    for child in element.findall("data"):
        attributes: dict[str, str] = {}
        for key, value in child.attrib.items():
            attributes[_local_name(key)] = value
        data.append(dict(sorted(attributes.items())))
    return IntentFilter(actions=actions, categories=categories, data=tuple(data))


def _effective_target_sdk(
    min_sdk: str | None, target_sdk: str | None, warnings: list[str]
) -> int | None:
    if target_sdk is not None:
        parsed = _parse_sdk(target_sdk)
        if parsed is None:
            warnings.append(
                "/manifest/uses-sdk[1]/@android:targetSdkVersion: value is not a "
                "numeric API level; exported defaults that depend on target SDK "
                "remain indeterminate."
            )
        return parsed
    if min_sdk is not None:
        parsed = _parse_sdk(min_sdk)
        if parsed is None:
            warnings.append(
                "/manifest/uses-sdk[1]/@android:minSdkVersion: value is not a "
                "numeric API level and targetSdkVersion is absent; exported defaults "
                "that depend on target SDK remain indeterminate."
            )
        return parsed
    # Android's documented targetSdkVersion default is minSdkVersion, whose own
    # default is API level 1 when both attributes are absent.
    return 1


def _parse_sdk(value: str) -> int | None:
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 1 else None


def _exported_state(
    kind: ComponentKind,
    explicit_exported: bool | None,
    exported_attribute_present: bool,
    has_intent_filters: bool,
    effective_target_sdk: int | None,
    source_locator: str,
    warnings: list[str],
) -> tuple[bool | None, str, str, bool]:
    explicit_locator = f"{source_locator}/@android:exported"
    if exported_attribute_present:
        if explicit_exported is None:
            return None, "indeterminate-nonliteral", explicit_locator, False
        return explicit_exported, "explicit", explicit_locator, False

    if kind is ComponentKind.PROVIDER:
        if effective_target_sdk is None:
            warnings.append(
                f"{source_locator}: provider omits android:exported and its default "
                "cannot be inferred without a numeric effective target SDK."
            )
            return None, "indeterminate-target-sdk", source_locator, False
        exported = effective_target_sdk < _PROVIDER_PRIVATE_BY_DEFAULT_TARGET_SDK
        source = (
            "inferred-provider-target-sdk-16-or-lower"
            if exported
            else "inferred-provider-target-sdk-17-or-higher"
        )
        return exported, source, source_locator, False

    if not has_intent_filters:
        return False, "inferred-no-intent-filter", source_locator, False
    if effective_target_sdk is None:
        warnings.append(
            f"{source_locator}: {kind.value} has intent filters but omits "
            "android:exported; a nonnumeric target SDK prevents determining whether "
            "legacy inference or the Android 12 explicit requirement applies."
        )
        return None, "indeterminate-target-sdk", source_locator, False
    if effective_target_sdk >= _ANDROID_12_TARGET_SDK:
        warnings.append(
            f"{source_locator}: targetSdkVersion {effective_target_sdk} requires "
            f"{kind.value} components with intent filters to declare "
            "android:exported explicitly; this manifest is invalid as declared and "
            "the effective export state was not inferred."
        )
        return None, "missing-required-explicit", source_locator, True
    return True, "inferred-from-intent-filter", source_locator, False


def _attack_surface_entry(component: ManifestComponent) -> AttackSurfaceEntry:
    evidence_locators = [component.source_locator]
    if component.exported_source_locator is not None:
        evidence_locators.append(component.exported_source_locator)

    uncertainty = _attack_surface_uncertainty(component)
    if component.kind is ComponentKind.PROVIDER:
        unguarded_operations = tuple(
            operation
            for operation, permission in (
                ("read", component.read_permission),
                ("write", component.write_permission),
            )
            if permission is None
        )
        for locator in (
            component.read_permission_source_locator,
            component.write_permission_source_locator,
        ):
            if locator is not None:
                evidence_locators.append(locator)
        if unguarded_operations == ("read", "write"):
            reason = "exported provider has no read or write permission guard"
        elif unguarded_operations:
            reason = (
                f"exported provider has no {unguarded_operations[0]} permission guard"
            )
        else:
            reason = "exported provider declares read and write permission guards"
        return AttackSurfaceEntry(
            component=component.name,
            kind=component.kind,
            permission=component.permission,
            read_permission=component.read_permission,
            write_permission=component.write_permission,
            unguarded_operations=unguarded_operations,
            reason=f"{uncertainty}{reason}",
            source_locator=component.source_locator,
            evidence_locators=_deduplicate(evidence_locators),
        )

    if component.permission is None:
        reason = "exported component has no permission guard"
        unguarded_operations = ("invoke",)
    else:
        reason = "exported component declares a permission guard"
        unguarded_operations = ()
        if component.permission_source_locator is not None:
            evidence_locators.append(component.permission_source_locator)
    return AttackSurfaceEntry(
        component=component.name,
        kind=component.kind,
        permission=component.permission,
        reason=f"{uncertainty}{reason}",
        source_locator=component.source_locator,
        unguarded_operations=unguarded_operations,
        evidence_locators=_deduplicate(evidence_locators),
    )


def _deduplicate(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _android_attr(element: ET.Element | None, name: str) -> str | None:
    if element is None:
        return None
    value = element.attrib.get(f"{{{ANDROID_NS}}}{name}")
    return value.strip() if value is not None and value.strip() else None


def _optional_bool_attr(
    element: ET.Element | None,
    name: str,
    *,
    warnings: list[str] | None = None,
    source_locator: str | None = None,
) -> bool | None:
    value = _android_attr(element, name)
    if value is None:
        return None
    normalized = value.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    if warnings is not None:
        locator = source_locator or f"@android:{name}"
        warnings.append(
            f"{locator}: value {value!r} is not a literal boolean; its effective "
            "value remains indeterminate without Android resource resolution."
        )
    return None


def _bool_attr(
    element: ET.Element | None,
    name: str,
    default: bool,
    *,
    warnings: list[str] | None = None,
    source_locator: str | None = None,
    unresolved_default: bool | None = None,
) -> bool:
    raw = _android_attr(element, name)
    if raw is None:
        return default
    value = _optional_bool_attr(
        element,
        name,
        warnings=warnings,
        source_locator=source_locator,
    )
    if value is not None:
        return value
    if unresolved_default is None:
        return default
    if warnings is not None:
        locator = source_locator or f"@android:{name}"
        warnings.append(
            f"{locator}: treated conservatively as "
            f"{'true' if unresolved_default else 'false'} in the boolean summary."
        )
    return unresolved_default


def _effective_enabled(
    application_enabled: bool | None, component_enabled: bool | None
) -> bool | None:
    if application_enabled is False or component_enabled is False:
        return False
    if application_enabled is True and component_enabled is True:
        return True
    return None


def _is_attack_surface_candidate(component: ManifestComponent) -> bool:
    if component.enabled is False or component.exported is False:
        return False
    # A target-SDK 31+ declaration that omits required android:exported is invalid
    # as declared rather than a potentially exported installable component.
    return component.exported_source != "missing-required-explicit"


def _attack_surface_uncertainty(component: ManifestComponent) -> str:
    states: list[str] = []
    if component.exported is None:
        states.append("export state is indeterminate")
    if component.enabled is None:
        states.append("enabled state is indeterminate")
    if not states:
        return ""
    return f"potential attack surface ({'; '.join(states)}); "


def _qualify_component(name: str, package_name: str) -> str:
    if name.startswith("."):
        return f"{package_name}{name}"
    if "." not in name:
        return f"{package_name}.{name}"
    return name


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1]


def _project_root(context: ToolContext) -> Path:
    if _PROJECT_ID_PATTERN.fullmatch(context.project_id) is None:
        raise ManifestError("invalid project identifier")
    try:
        data_root = context.data_dir.expanduser().resolve()
        projects_path = data_root / "projects"
        if projects_path.resolve() != projects_path:
            raise ManifestError("projects area cannot be a symbolic link")
        project_path = projects_path / context.project_id
        project_root = project_path.resolve()
        if project_root != project_path:
            raise ManifestError("project area cannot be a symbolic link")
        project_root.relative_to(data_root)
    except ManifestError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ManifestError(
            "project area escapes or cannot resolve under data_dir"
        ) from exc
    return project_root


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"manifest path must be within {root}") from exc
