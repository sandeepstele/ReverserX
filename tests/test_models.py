import pytest

from reverserx.core.models import Finding, Project


def test_models_have_stable_type_prefixes_and_schema_version() -> None:
    project = Project(slug="fixture-app", name="Fixture App")
    finding = Finding(project_id=project.id, title="Candidate", description="Test")

    assert project.id.startswith("prj_")
    assert finding.id.startswith("fnd_")
    assert project.schema_version == "1.0"
    assert finding.inference is True


@pytest.mark.parametrize(
    "slug", ["Invalid", "bad_slug", "-leading", "trailing-", "ümlaut"]
)
def test_project_slug_validation(slug: str) -> None:
    with pytest.raises(ValueError):
        Project(slug=slug, name="Invalid")
