from triagetool import store

ADVISORY = {
    "ghsa": "GHSA-2222-3333-4444",
    "org": "acme",
    "repo": "repo-a",
    "state": "triage",
    "severity": "high",
    "cve": "",
    "title": "Path traversal in export",
    "created": "2026-10-01",
    "updated": "2026-10-02",
}


def test_advisories_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")
    assert store.load_advisories() == {"fetched_at": "", "advisories": []}
    store.save_advisories([ADVISORY])
    data = store.load_advisories()
    assert data["advisories"] == [ADVISORY]
    assert data["fetched_at"]


def test_replace_repo_keeps_other_repos():
    other = {**ADVISORY, "ghsa": "GHSA-5555-6666-7777", "repo": "repo-b"}
    fresh = {**ADVISORY, "state": "published"}
    assert store.replace_repo([ADVISORY, other], "acme/repo-a", [fresh]) == [other, fresh]


def test_verdict_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")
    ghsa = ADVISORY["ghsa"]
    assert store.load_verdicts(ghsa) == {}
    verdict = {"tool": "legit", "ran_at": "2026-10-30T10:00:00+00:00", "result": {"verdict": "valid"}}
    store.save_verdict(ghsa, verdict)
    assert store.load_verdicts(ghsa) == {"legit": verdict}
    assert not store.verdict_path(ghsa, "dedup").exists()
