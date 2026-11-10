import pytest

from triagetool import claim, host, threatmodel, verdict

from .conftest import FIRST_ID, SECOND_ID, THIRD_ID, advisory


def test_has_file(code):
    assert host.has_file(code, "code/src/a.py")
    assert host.has_file(code, "code/src/a.py:12-20")
    assert not host.has_file(code, "code/src/missing.py")
    assert not host.has_file(code, "code/src/a.py (see above)")


def test_repo_name():
    assert host.repo_name("acme/app") == "acme/app"
    assert host.repo_name("acme\tapp") == "acme/app"
    for bad in ["acme", "acme/app/extra", "acme/..", "../app"]:
        with pytest.raises(host.ToolError):
            host.repo_name(bad)


def test_claim_stays_small_whatever_the_agent_wrote():
    long = "x" * 5000
    raw = {"summary": long, "attacker": "a", "action": "b", "impact": "c", "steps": [long] * 50, "places": ["p"] * 50}
    kept = claim.validate({**raw, "severity": "critical"})
    assert set(kept) == {"summary", "attacker", "action", "impact", "steps", "places"}
    assert len(kept["summary"]) == host.MAX_LINE
    assert len(kept["steps"]) == claim.MAX_STEPS and len(kept["steps"][0]) == host.MAX_LINE
    assert len(kept["places"]) == claim.MAX_PLACES


def answer(holds=("yes", "yes"), **overrides):
    return {
        "headline": "h",
        "why": "w",
        "full": "the whole story",
        "attacker_needs": "n",
        "boundary": "crossed",
        "links": [{"fact": "f", "holds": held, "where": "code/src/a.py:1"} for held in holds],
        "duplicate_of": None,
        "severity": "medium",
        "severity_why": "s",
        "ask": "",
        **overrides,
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (answer(), "probably_real"),
        (answer(duplicate_of=SECOND_ID), "probably_real"),
        (answer(holds=("yes", "no")), "probably_invalid"),
        (answer(boundary="not_crossed"), "probably_invalid"),
        (answer(boundary="undocumented"), "unsure"),
        (answer(holds=("yes", "unknown")), "unsure"),
        (answer(holds=("yes", "unknown"), ask="Which version?"), "ask_reporter"),
    ],
)
def test_verdict_follows_from_the_facts(code, raw, expected):
    assert verdict.decide(verdict.validate(raw, {SECOND_ID}, code)) == expected


@pytest.mark.parametrize(
    "bad",
    [
        {"duplicate_of": "GHSA-zzzz-zzzz-zzzz"},
        {"links": [{"fact": "f", "holds": "maybe", "where": None}]},
        {"boundary": "fuzzy"},
        {"severity": "apocalyptic"},
    ],
)
def test_verdict_rejects(code, bad):
    with pytest.raises(ValueError):
        verdict.validate(answer(**bad), {SECOND_ID}, code)


@pytest.mark.parametrize("where", [None, "", "code/nope.py", "see the upload handler"])
def test_a_fact_that_points_at_no_real_file_does_not_count_as_checked(code, where):
    raw = answer(links=[{"fact": "f", "holds": "yes", "where": where}])
    checked = verdict.validate(raw, {SECOND_ID}, code)
    assert checked["links"] == [{"fact": "f", "holds": "unknown", "where": None}]
    assert verdict.decide(checked) == "unsure"


def test_an_empty_duplicate_is_no_duplicate(code):
    assert verdict.validate(answer(duplicate_of=""), {SECOND_ID}, code)["duplicate_of"] is None


def test_a_report_is_never_compared_with_a_later_report_in_triage():
    later = {**advisory(SECOND_ID), "created_at": "2026-10-02T10:00:00Z"}
    advisories = [advisory(FIRST_ID), later]
    claims = {FIRST_ID: {"summary": "first"}, SECOND_ID: {"summary": "second"}}
    assert f"others/{SECOND_ID}.json" not in verdict.other_files(advisories, claims, FIRST_ID)
    assert f"others/{FIRST_ID}.json" in verdict.other_files(advisories, claims, SECOND_ID)


def test_other_files_hide_the_target_and_every_report_still_in_triage():
    advisories = [advisory(FIRST_ID), advisory(SECOND_ID), advisory(THIRD_ID, "closed")]
    files = verdict.other_files(advisories, {FIRST_ID: {"summary": "restated"}}, SECOND_ID)
    assert set(files) == {f"others/{FIRST_ID}.json", f"others/{THIRD_ID}.json", "others/index.txt"}
    assert "A very long report." not in files[f"others/{FIRST_ID}.json"]
    assert "restated" in files[f"others/{FIRST_ID}.json"]
    assert "A very long report." in files[f"others/{THIRD_ID}.json"]
    assert SECOND_ID not in files["others/index.txt"]


def audit_raw(**statuses):
    checks = {}
    for key in threatmodel.QUESTIONS:
        status = statuses.get(key, "answered")
        checks[key] = {"status": status, "where": [] if status == "missing" else ["code/src/a.py:1"], "note": "n"}
    return checks


def test_threatmodel_rating_follows_the_core_questions(code):
    def rate(**statuses):
        return threatmodel.validate(audit_raw(**statuses), code)["rating"]

    assert rate() == "documented"
    assert rate(reporting="missing", versions="missing") == "documented"
    assert rate(boundary="partial") == "partial"
    assert rate(trusted="missing") == "partial"
    assert rate(trusted="missing", attacker="missing", boundary="missing") == "missing"


@pytest.mark.parametrize("where", [[], ["code/nope.md"]])
def test_an_answer_that_points_at_no_real_file_counts_as_missing(code, where):
    raw = {**audit_raw(), "boundary": {"status": "answered", "where": where, "note": "n"}}
    audit = threatmodel.validate(raw, code)
    assert audit["checks"]["boundary"] == {"status": "missing", "where": [], "note": "n"}
    assert audit["rating"] == "partial"


def test_threatmodel_rejects_an_unknown_status(code):
    raw = {**audit_raw(), "boundary": {"status": "fine", "where": ["code/src/a.py"], "note": "n"}}
    with pytest.raises(ValueError):
        threatmodel.validate(raw, code)


def test_an_agent_killed_by_an_interrupt_stores_nothing(tmp_path, monkeypatch):
    class Killed:
        stdout = ""
        stderr = "container removed"

    def interrupted_run(command, **options):
        host.STOPPING.set()
        return Killed

    monkeypatch.setattr(host.subprocess, "run", interrupted_run)
    try:
        with pytest.raises(host.Stopped):
            host.ask(claim.AGENT, {}, tmp_path)
        with pytest.raises(host.Stopped):
            host.ask(claim.AGENT, {}, tmp_path)
    finally:
        host.STOPPING.clear()


def test_the_tldr_write_up_is_one_paragraph_and_the_others_keep_every_part():
    from triagetool import writeup

    checked = {"links": [{"fact": "f", "holds": "yes", "where": None}]}
    assert writeup.validate({"finding": "x" * 999}, "tldr", checked) == {"finding": "x" * 330}
    assert list(writeup.agent("tldr").schema["properties"]) == ["finding"]
    assert "facts" in writeup.agent("short").schema["properties"]
    with pytest.raises(ValueError):
        writeup.validate({"finding": "f", "attacker": "a", "facts": [], "severity": "s", "ask": ""}, "short", checked)
