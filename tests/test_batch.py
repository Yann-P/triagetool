import argparse
from contextlib import contextmanager

import pytest

from triagetool import batch, host, store

A, B, C = "GHSA-2222-3333-4444", "GHSA-5555-6666-7777", "GHSA-8888-9999-cccc"


def raw(ghsa, state="triage"):
    return {
        "ghsa_id": ghsa,
        "cve_id": None,
        "state": state,
        "severity": "high",
        "summary": "  Path traversal\n in export ",
        "created_at": "2026-10-01T10:00:00Z",
        "updated_at": "2026-10-02T10:00:00Z",
    }


def test_read_repos(tmp_path):
    path = tmp_path / "repos.txt"
    path.write_text("# comment\nacme/repo-a\n\nacme\trepo-b\nacme repo-c  # trailing\n")
    assert batch.read_repos(path) == ["acme/repo-a", "acme/repo-b", "acme/repo-c"]
    path.write_text("acme/repo-a/extra\n")
    with pytest.raises(host.ToolError):
        batch.read_repos(path)


def test_todo(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")
    advisories = [
        host.summary(raw(A), "acme/r"),
        host.summary(raw(B), "acme/r"),
        host.summary(raw(C, "draft"), "acme/r"),
    ]
    store.save_verdict(A, {"tool": "dedup", "ran_at": "", "result": {}})
    store.save_verdict(A, {"tool": "legit", "ran_at": "", "error": "boom"})
    assert batch.todo(advisories, force=False) == [(A, "legit"), (B, "dedup"), (B, "legit")]
    assert batch.todo(advisories, force=True) == [(A, "dedup"), (A, "legit"), (B, "dedup"), (B, "legit")]


def test_main_clones_once_per_repo_with_work(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")
    repos = tmp_path / "repos.txt"
    repos.write_text("acme/busy\nacme/quiet\nacme/gone\n")
    calls = []

    @contextmanager
    def workdir():
        yield tmp_path / "work"

    def fetch_advisories(repo):
        if repo == "acme/gone":
            raise host.ToolError("gh exited 1")
        return [raw(A), raw(B, "published")] if repo == "acme/busy" else [raw(C, "draft")]

    def judge(tool, ghsa, work):
        if tool is batch.TOOLS["legit"]:
            raise host.ToolError("rejected: no")
        return {"relation": "distinct"}

    monkeypatch.setattr(host, "workdir", workdir)
    monkeypatch.setattr(host, "fetch_advisories", fetch_advisories)
    monkeypatch.setattr(host, "write_ghsas", lambda advisories, work: calls.append(("write", len(advisories))))
    monkeypatch.setattr(host, "clone", lambda repo, since, work: calls.append(("clone", repo)))
    monkeypatch.setattr(host, "judge", judge)

    batch.main(argparse.Namespace(repos=repos, since="1 year ago", force=False))

    assert calls == [("write", 2), ("clone", "acme/busy")]
    saved = store.load_advisories()["advisories"]
    assert [adv["ghsa"] for adv in saved] == [A, B, C]
    assert saved[0]["title"] == "Path traversal in export"
    assert store.load_verdicts(A)["dedup"]["result"] == {"relation": "distinct"}
    assert store.load_verdicts(A)["legit"]["error"] == "rejected: no"
    assert store.load_verdicts(B) == {}
    out = capsys.readouterr().out
    assert "acme/gone: gh exited 1" in out
    assert out.endswith("2 repos, ran 2, skipped 0, errors 1\n")
