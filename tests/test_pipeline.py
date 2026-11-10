import threading
from contextlib import contextmanager

import pytest

from triagetool import claim, host, pipeline, store, threatmodel, verdict, writeup

from .conftest import FIRST_ID, SECOND_ID, THIRD_ID, advisory


def test_read_repos(tmp_path):
    path = tmp_path / "repos.txt"
    path.write_text("# comment\nacme/repo-a\n\nacme\trepo-b\nacme repo-c  # trailing\n")
    assert pipeline.read_repos([str(path), "acme/app"]) == ["acme/repo-a", "acme/repo-b", "acme/repo-c", "acme/app"]
    with pytest.raises(host.ToolError):
        pipeline.read_repos(["not-a-repo"])


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    """GitHub and the sandbox replaced by functions that record what they were asked."""
    calls = []
    lock = threading.Lock()

    def note(*call):
        with lock:
            calls.append(call)

    def fetch_advisories(repo):
        if repo == "acme/gone":
            raise host.ToolError("gh exited 1")
        if repo == "acme/busy":
            return [advisory(FIRST_ID), advisory(SECOND_ID), advisory(THIRD_ID, "closed")]
        return [advisory(THIRD_ID, "draft")]

    def clone(repo, since, destination):
        note("clone", repo)

    def audit(code, base):
        note("audit")
        return {"rating": "partial"}

    def distill(report, base):
        note("claim", report["ghsa_id"])
        return {"summary": "s"}

    def investigate(target, advisories, claims, audit, earlier, code, base):
        note("verdict", target, sorted(claims), audit)
        if "previous" in earlier:
            note("second look", target, earlier["hint"])
        if target == SECOND_ID:
            raise host.ToolError("rejected: no")
        return {"verdict": "unsure"}

    @contextmanager
    def nothing():
        note("sandbox")
        yield tmp_path

    monkeypatch.setattr(host, "fetch_advisories", fetch_advisories)
    monkeypatch.setattr(host, "clone", clone)
    monkeypatch.setattr(host, "sandbox", nothing)
    monkeypatch.setattr(host, "workdir", nothing)
    monkeypatch.setattr(threatmodel, "audit", audit)
    monkeypatch.setattr(claim, "distill", distill)
    monkeypatch.setattr(verdict, "investigate", investigate)

    def write(level, record, base):
        note("text", level)
        return {"finding": f"{level} wording"}

    monkeypatch.setattr(writeup, "write", write)
    return calls


def run(force=False, retry_errors=True):
    repos = ["acme/busy", "acme/quiet", "acme/gone"]
    pipeline.run(repos, "1 year ago", force, 2, retry_errors)


def test_run_analyses_only_reports_in_triage_and_pays_once(fakes, capsys):
    run()

    assert store.repos() == ["acme/busy", "acme/quiet"]
    assert [call for call in fakes if call[0] == "clone"] == [("clone", "acme/busy")]
    assert fakes.count(("audit",)) == 1
    assert ("verdict", FIRST_ID, [FIRST_ID, SECOND_ID], {"rating": "partial"}) in fakes
    assert store.load("acme/busy", FIRST_ID)["verdict"] == {"verdict": "unsure"}
    assert store.load("acme/busy", SECOND_ID)["error"] == "rejected: no"
    assert store.load("acme/busy", THIRD_ID) == {}
    out = capsys.readouterr().out
    assert "acme/gone: gh exited 1" in out
    assert "2 repositories, 2 reports to analyse" in out

    fakes.clear()
    run()

    assert [call[:2] for call in fakes if call[0] != "sandbox"] == [
        ("clone", "acme/busy"),
        ("verdict", SECOND_ID),
    ], "the failed check runs again, with the audit and both claims taken from the store"

    fakes.clear()
    run(force=True)
    assert sorted(call[:2] for call in fakes if call[0] in ("audit", "claim")) == [
        ("audit",),
        ("claim", FIRST_ID),
        ("claim", SECOND_ID),
    ]


def test_run_starts_nothing_when_every_report_has_a_verdict(fakes):
    store.save("acme/busy", FIRST_ID, {"claim": {}, "verdict": {}, "texts": {}})
    store.save("acme/busy", SECOND_ID, {"claim": {}, "verdict": {}, "texts": {}})
    run()
    assert fakes == []


def test_a_verdict_is_written_up_at_three_lengths_and_can_be_rewritten_alone(fakes):
    run()
    wording = {"finding": "short wording"}
    assert store.load("acme/busy", FIRST_ID)["texts"]["short"] == wording
    assert sorted(store.load("acme/busy", FIRST_ID)["texts"]) == ["full", "medium", "short", "tldr"]
    assert "texts" not in store.load("acme/busy", SECOND_ID), "nothing to write up when the check failed"

    fakes.clear()
    pipeline.run(["acme/busy"], "1 year ago", False, 2, rewrite=True)
    kinds = sorted(call[0] for call in fakes)
    assert kinds == ["clone", "sandbox", "sandbox", "text", "text", "text", "text", "verdict"], (
        "the write-ups are redone without investigating the finished report again"
    )


def test_an_older_verdict_only_gets_its_write_ups(fakes):
    store.save("acme/busy", FIRST_ID, {"claim": {"summary": "s"}, "verdict": {"headline": "kept"}})
    store.save("acme/busy", SECOND_ID, {"claim": {}, "verdict": {}, "texts": {}})
    run()
    assert not [call for call in fakes if call[0] in ("verdict", "claim")]
    record = store.load("acme/busy", FIRST_ID)
    assert record["verdict"] == {"headline": "kept"} and len(record["texts"]) == 4


def test_reports_wait_when_the_threat_model_audit_fails(fakes, monkeypatch):
    def audit(code, base):
        raise host.ToolError("agent failed")

    monkeypatch.setattr(threatmodel, "audit", audit)
    run()
    assert store.load("acme/busy", "threatmodel")["error"] == "agent failed"
    assert store.load("acme/busy", FIRST_ID) == {}
    assert not [call for call in fakes if call[0] in ("claim", "verdict")]


def test_a_repository_that_cannot_be_cloned_is_reported_and_skipped(fakes, monkeypatch, capsys):
    def clone(repo, since, destination):
        raise host.ToolError("git exited 128")

    monkeypatch.setattr(host, "clone", clone)
    run()
    assert "acme/busy: git exited 128" in capsys.readouterr().out
    assert store.load("acme/busy", "threatmodel") == {}


def test_a_second_look_passes_the_hint_and_keeps_it_on_the_new_record(fakes):
    run()
    first_answer = store.load("acme/busy", FIRST_ID)["verdict"]
    store.save("acme/busy", FIRST_ID, {"claim": {"summary": "s"}, "previous": first_answer, "hint": "needs admin"})
    fakes.clear()

    pipeline.look_again("acme/busy", [FIRST_ID], reaudit=False, since="1 year ago", jobs=2)

    assert ("second look", FIRST_ID, "needs admin") in fakes
    assert ("audit",) not in fakes
    record = store.load("acme/busy", FIRST_ID)
    assert record["hint"] == "needs admin" and "verdict" in record and "previous" not in record


def test_a_second_look_that_cannot_start_says_why_and_loses_nothing(fakes, monkeypatch):
    @contextmanager
    def no_sandbox():
        raise host.ToolError("set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY")
        yield

    monkeypatch.setattr(host, "sandbox", no_sandbox)
    store.save("acme/busy", FIRST_ID, {"claim": {"summary": "s"}, "previous": {"headline": "old"}, "hint": ""})
    pipeline.look_again("acme/busy", [FIRST_ID], reaudit=False, since="1 year ago", jobs=2)
    record = store.load("acme/busy", FIRST_ID)
    assert record["error"] == "set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY"
    assert record["previous"] == {"headline": "old"}


def test_an_automatic_round_leaves_alone_what_failed_before(fakes, monkeypatch):
    run()
    assert "error" in store.load("acme/busy", SECOND_ID)
    fakes.clear()
    run(retry_errors=False)
    assert fakes == [], "the failed check is not paid for again every few minutes"

    store.save("acme/busy", "threatmodel", {"error": "audit failed"})
    store.save("acme/busy", FIRST_ID, {})
    run(retry_errors=False)
    assert fakes == [], "nor is anything in a repository whose audit failed"
