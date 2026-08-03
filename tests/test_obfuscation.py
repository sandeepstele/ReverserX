from pathlib import Path

import pytest

from reverserx.tools.base import ToolContext
from reverserx.tools.static.obfuscation import (
    ObfuscationDetectInput,
    ObfuscationDetectTool,
    ObfuscationKind,
    detect_obfuscation,
)


def test_clean_source_does_not_trigger_obfuscation(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "EncryptionManager.java").write_text(
        """
        package com.example;
        public class EncryptionManager {
            public String encryptRequest(String payload) { return payload; }
            public String decryptResponse(String payload) { return payload; }
        }
        """,
        encoding="utf-8",
    )

    report = detect_obfuscation(source)

    assert report.kind is ObfuscationKind.NONE
    assert report.file_count == 1
    assert report.class_count == 1
    assert report.confidence >= 0.8
    assert not report.likely_products


def test_representative_clean_corpus_stays_below_false_positive_threshold(
    tmp_path: Path,
) -> None:
    source = tmp_path / "clean-corpus"
    source.mkdir()
    for index in range(30):
        (source / f"FeatureComponent{index}.java").write_text(
            f"""
            package com.example.features;
            public class FeatureComponent{index} {{
                public String resolveConfiguration{index}(String inputValue) {{
                    return inputValue.trim();
                }}
                public boolean validateResponse{index}(String responseValue) {{
                    return responseValue != null;
                }}
            }}
            """,
            encoding="utf-8",
        )

    report = detect_obfuscation(source)

    assert report.class_count == 30
    assert report.method_count >= 60
    assert report.short_name_ratio == 0.0
    assert report.kind is ObfuscationKind.NONE
    assert report.confidence >= 0.9
    assert all(signal.score < 0.55 for signal in report.signals)


def test_mixed_obfuscation_reports_evidence_and_markers(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    for index in range(30):
        name = chr(ord("a") + (index % 26))
        (source / f"{index}.java").write_text(
            f"""
            class {name} {{
                String a() throws Exception {{
                    Class.forName("x").getDeclaredMethod("a").invoke(this);
                    return "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789+/";
                }}
            }}
            // StringFog marker
            """,
            encoding="utf-8",
        )
    (source / "flow.smali").write_text(
        ".class public La;\n.method public a()V\n"
        + ("goto :state\n:state\npacked-switch p0, :table\n" * 80)
        + ".end method\n",
        encoding="utf-8",
    )

    report = detect_obfuscation(source)

    assert report.kind is ObfuscationKind.MIXED
    assert report.confidence >= 0.9
    assert report.short_name_ratio > 0.8
    assert "StringFog" in report.likely_products
    assert any(signal.name == "short-identifiers" for signal in report.signals)
    assert any(
        signal.locators for signal in report.signals if "StringFog" in signal.name
    )


def test_obfuscation_tool_uses_project_runtime_scope(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    source = data_dir / "projects" / "prj_fixture" / "src"
    source.mkdir(parents=True)
    (source / "Example.java").write_text("class Example {}", encoding="utf-8")

    execution = ObfuscationDetectTool().execute(
        ToolContext(project_id="prj_fixture", data_dir=data_dir),
        ObfuscationDetectInput(source_root=source),
    )

    assert execution.output["file_count"] == 1
    assert execution.output["kind"] == "none-detected"


def test_obfuscation_tool_rejects_another_project_source(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    source = data_dir / "projects" / "prj_other" / "src"
    source.mkdir(parents=True)
    (source / "Example.java").write_text("class Example {}", encoding="utf-8")

    with pytest.raises(ValueError, match="must be within"):
        ObfuscationDetectTool().execute(
            ToolContext(project_id="prj_fixture", data_dir=data_dir),
            ObfuscationDetectInput(source_root=source),
        )
