"""Evidence-based heuristics for initial Android source obfuscation detection."""

from __future__ import annotations

import math
import re
from collections import Counter
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from reverserx.tools.base import BaseTool, ToolContext, ToolExecution

SOURCE_SUFFIXES = frozenset({".java", ".kt", ".smali"})
CLASS_PATTERN = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Za-z_$][\w$]*)")
SMALI_CLASS_PATTERN = re.compile(r"^\.class\b.*?L(?:.*/)?([^/;]+);", re.MULTILINE)
METHOD_PATTERN = re.compile(
    r"(?:\b(?:public|private|protected|internal|static|final|synchronized|native|abstract)\s+)*"
    r"(?:fun\s+|[\w$<>\[\],.?]+\s+)([A-Za-z_$][\w$]*)\s*\(",
    re.MULTILINE,
)
SMALI_METHOD_PATTERN = re.compile(r"^\.method\b.*?\s([\w$<>]+)\(", re.MULTILINE)
REFLECTION_PATTERN = re.compile(
    r"Class\.forName|getDeclaredMethod|getDeclaredField|java\.lang\.reflect|\.invoke\s*\(",
)
BASE64_STRING_PATTERN = re.compile(r'"[A-Za-z0-9+/]{32,}={0,2}"')
HEX_STRING_PATTERN = re.compile(r'"(?:[0-9a-fA-F]{2}){16,}"')
CONTROL_FLOW_PATTERN = re.compile(r"\b(?:switch|tableswitch|lookupswitch|goto)\b")


class ObfuscationError(ValueError):
    """Raised when a source tree cannot be inspected safely."""


class ObfuscationKind(StrEnum):
    NONE = "none-detected"
    NAME = "name-obfuscation"
    STRING = "string-obfuscation"
    CONTROL_FLOW = "control-flow-obfuscation"
    MIXED = "mixed-or-custom"


class ObfuscationSignal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    score: float = Field(ge=0, le=1)
    evidence: str
    locators: tuple[str, ...] = ()


class ObfuscationReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    source_root: str
    kind: ObfuscationKind
    confidence: float = Field(ge=0, le=1)
    likely_products: tuple[str, ...] = ()
    file_count: int = Field(ge=0)
    class_count: int = Field(ge=0)
    method_count: int = Field(ge=0)
    short_name_ratio: float = Field(ge=0, le=1)
    identifier_entropy: float = Field(ge=0)
    signals: tuple[ObfuscationSignal, ...] = ()
    warnings: tuple[str, ...] = ()


class ObfuscationDetectInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_root: Path
    max_files: int = Field(default=100_000, ge=1, le=1_000_000)
    max_file_bytes: int = Field(default=5_000_000, ge=1_024, le=50_000_000)


class ObfuscationDetectTool(BaseTool[ObfuscationDetectInput]):
    name = "detect_obfuscation"
    description = (
        "Detect evidence of name, string, reflection, and control-flow obfuscation."
    )
    version = "1.0.0"
    input_model = ObfuscationDetectInput

    def execute(
        self, context: ToolContext, arguments: ObfuscationDetectInput
    ) -> ToolExecution:
        root = arguments.source_root.expanduser().resolve(strict=True)
        projects_root = (context.data_dir / "projects").expanduser().resolve()
        project_root = (projects_root / context.project_id).resolve()
        _require_within(project_root, projects_root)
        _require_within(root, project_root)
        report = detect_obfuscation(
            root,
            max_files=arguments.max_files,
            max_file_bytes=arguments.max_file_bytes,
        )
        return ToolExecution(output=report.model_dump(mode="json"))


def detect_obfuscation(
    source_root: Path,
    *,
    max_files: int = 100_000,
    max_file_bytes: int = 5_000_000,
) -> ObfuscationReport:
    root = source_root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ObfuscationError(f"source root is not a directory: {root}")

    class_names: list[str] = []
    method_names: list[str] = []
    reflection_count = 0
    encoded_string_count = 0
    control_flow_count = 0
    total_lines = 0
    file_count = 0
    marker_locators: dict[str, list[str]] = {
        "DexGuard": [],
        "Allatori": [],
        "StringFog": [],
    }
    warnings: list[str] = []

    for path in _source_files(root):
        if file_count >= max_files:
            warnings.append(f"file limit reached at {max_files}")
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            warnings.append(f"skipped oversized file: {path.relative_to(root)}")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        file_count += 1
        relative = path.relative_to(root).as_posix()
        total_lines += text.count("\n") + 1
        class_names.extend(CLASS_PATTERN.findall(text))
        class_names.extend(SMALI_CLASS_PATTERN.findall(text))
        method_names.extend(METHOD_PATTERN.findall(text))
        method_names.extend(SMALI_METHOD_PATTERN.findall(text))
        reflection_count += len(REFLECTION_PATTERN.findall(text))
        encoded_string_count += len(BASE64_STRING_PATTERN.findall(text))
        encoded_string_count += len(HEX_STRING_PATTERN.findall(text))
        control_flow_count += len(CONTROL_FLOW_PATTERN.findall(text))
        lowered = text.lower()
        if "dexguard" in lowered:
            marker_locators["DexGuard"].append(relative)
        if "allatori" in lowered:
            marker_locators["Allatori"].append(relative)
        if "stringfog" in lowered:
            marker_locators["StringFog"].append(relative)

    identifiers = class_names + [
        name for name in method_names if name not in {"<init>", "<clinit>"}
    ]
    short_names = [name for name in identifiers if len(name) <= 2]
    short_ratio = len(short_names) / len(identifiers) if identifiers else 0.0
    entropy = _entropy("".join(identifiers))
    name_score = 0.0
    if len(identifiers) >= 20:
        name_score = min(1.0, max(0.0, (short_ratio - 0.2) / 0.6))
    reflection_density = reflection_count / max(file_count, 1)
    reflection_score = min(1.0, reflection_density / 2.0)
    string_density = encoded_string_count / max(file_count, 1)
    string_score = min(1.0, string_density / 3.0)
    control_density = control_flow_count / max(total_lines / 1_000, 1.0)
    control_score = min(1.0, max(0.0, (control_density - 8.0) / 40.0))

    signals = (
        ObfuscationSignal(
            name="short-identifiers",
            score=name_score,
            evidence=(
                f"{len(short_names)} of {len(identifiers)} class/method identifiers "
                f"have length <= 2 ({short_ratio:.1%})"
            ),
        ),
        ObfuscationSignal(
            name="reflection-density",
            score=reflection_score,
            evidence=f"{reflection_count} reflection-related calls across {file_count} files",
        ),
        ObfuscationSignal(
            name="encoded-string-density",
            score=string_score,
            evidence=f"{encoded_string_count} long base64/hex string candidates",
        ),
        ObfuscationSignal(
            name="control-flow-density",
            score=control_score,
            evidence=(
                f"{control_flow_count} switch/goto instructions across "
                f"{total_lines} lines ({control_density:.2f} per 1K lines)"
            ),
        ),
    )
    active = [
        (ObfuscationKind.NAME, name_score),
        (ObfuscationKind.STRING, string_score),
        (ObfuscationKind.CONTROL_FLOW, control_score),
    ]
    strong = [item for item in active if item[1] >= 0.55]
    if len(strong) > 1 or (reflection_score >= 0.65 and strong):
        kind = ObfuscationKind.MIXED
        confidence = max(score for _, score in strong)
    elif strong:
        kind, confidence = max(strong, key=lambda item: item[1])
    else:
        kind = ObfuscationKind.NONE
        confidence = min(0.95, 1.0 - max(score for _, score in active))

    likely_products = tuple(
        product for product, locators in marker_locators.items() if locators
    )
    marker_signals = tuple(
        ObfuscationSignal(
            name=f"product-marker:{product}",
            score=0.9,
            evidence=f"found explicit {product} marker",
            locators=tuple(sorted(set(locators))[:20]),
        )
        for product, locators in marker_locators.items()
        if locators
    )
    if likely_products:
        confidence = max(confidence, 0.9)
        if kind is ObfuscationKind.NONE:
            kind = ObfuscationKind.MIXED

    return ObfuscationReport(
        source_root=str(root),
        kind=kind,
        confidence=round(confidence, 4),
        likely_products=likely_products,
        file_count=file_count,
        class_count=len(class_names),
        method_count=len(method_names),
        short_name_ratio=round(short_ratio, 4),
        identifier_entropy=round(entropy, 4),
        signals=signals + marker_signals,
        warnings=tuple(warnings),
    )


def _source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if (
            path.is_symlink()
            or not path.is_file()
            or path.suffix.lower() not in SOURCE_SUFFIXES
        ):
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def _require_within(path: Path, root: Path) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ObfuscationError(f"source root must be within {root}") from exc
