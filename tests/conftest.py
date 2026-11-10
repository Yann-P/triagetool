import pytest

from triagetool import store

FIRST_ID = "GHSA-2222-3333-4444"
SECOND_ID = "GHSA-5555-6666-7777"
THIRD_ID = "GHSA-8888-9999-cccc"


def advisory(ghsa, state="triage", author="mallory", severity="critical"):
    """An advisory with the fields GitHub returns and this tool reads."""
    return {
        "ghsa_id": ghsa,
        "cve_id": None,
        "state": state,
        "severity": severity,
        "summary": "  Path traversal\n in export ",
        "description": "A very long report.",
        "vulnerabilities": [],
        "created_at": "2026-10-01T10:00:00Z",
        "author": {"login": author} if author else None,
        "html_url": f"https://github.com/acme/app/security/advisories/{ghsa}",
    }


@pytest.fixture(autouse=True)
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")


@pytest.fixture
def code(tmp_path):
    (tmp_path / "code" / "src").mkdir(parents=True)
    (tmp_path / "code" / "src" / "a.py").write_text("x")
    return tmp_path / "code"
