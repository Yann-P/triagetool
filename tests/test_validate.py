import subprocess

import pytest

from triagetool import dedup, host, legit

TARGET = "GHSA-aaaa-bbbb-cccc"
OTHER = "GHSA-dddd-eeee-ffff"


@pytest.fixture
def work(tmp_path):
    (tmp_path / "ghsas").mkdir()
    for gid in (TARGET, OTHER):
        (tmp_path / "ghsas" / f"{gid}.json").write_text("{}")
    code = tmp_path / "code"
    (code / "src").mkdir(parents=True)
    (code / "src" / "a.py").write_text("x")
    git = ["git", "-C", str(code), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "x"], check=True)
    return tmp_path


def head(work):
    git = ["git", "-C", str(work / "code"), "rev-parse", "HEAD"]
    return subprocess.run(git, check=True, capture_output=True, text=True).stdout.strip()


def test_has_file(work):
    assert host.has_file(work, "code/src/a.py")
    assert host.has_file(work, "code/src/a.py:12-20")
    assert not host.has_file(work, "code/src/missing.py")
    assert not host.has_file(work, f"ghsas/{TARGET}.json")
    assert not host.has_file(work, "code/src/a.py (see above)")


def dedup_raw(**overrides):
    return {
        "relation": "same_bug",
        "duplicate_of": OTHER,
        "fix_commit": None,
        "evidence": ["code/src/a.py:1"],
        "rejected": [{"ghsa_id": OTHER, "reason": "older"}],
        "rationale": "ok",
        **overrides,
    }


def test_dedup_accepts(work):
    out = dedup.validate(dedup_raw(fix_commit=head(work)), TARGET, work)
    assert out["duplicate_of"] == OTHER


@pytest.mark.parametrize(
    "bad",
    [
        {"fix_commit": "deadbeef"},
        {"duplicate_of": TARGET},
        {"relation": "distinct"},
        {"evidence": ["code/nope.py"]},
        {"rejected": [{"ghsa_id": "GHSA-zzzz-zzzz-zzzz", "reason": ""}]},
    ],
)
def test_dedup_rejects(work, bad):
    with pytest.raises(ValueError):
        dedup.validate(dedup_raw(**bad), TARGET, work)


def legit_raw(**overrides):
    return {
        "threat_model": "missing",
        "threat_model_sources": [],
        "attacker": "anyone",
        "gain": "code execution",
        "in_scope": "yes",
        "chain": "complete",
        "steps": [{"claim": "input reaches eval", "evidence": ["code/src/a.py"], "status": "holds"}],
        "open_questions": [],
        "rationale": "ok",
        **overrides,
    }


def test_legit_verdicts(work):
    assert legit.validate(legit_raw(), TARGET, work)["verdict"] == "valid"
    assert legit.validate(legit_raw(in_scope="no"), TARGET, work)["verdict"] == "invalid"
    assert legit.validate(legit_raw(in_scope="unclear"), TARGET, work)["verdict"] == "uncertain"


@pytest.mark.parametrize(
    "bad",
    [
        {"threat_model": "documented"},
        {"threat_model_sources": ["code/src/a.py"]},
        {"steps": [{"claim": "c", "evidence": [], "status": "fails"}]},
        {"steps": []},
        {"chain": "broken"},
    ],
)
def test_legit_rejects(work, bad):
    with pytest.raises(ValueError):
        legit.validate(legit_raw(**bad), TARGET, work)
