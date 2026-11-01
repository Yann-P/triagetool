from triagetool import dedup, legit, render

ADVISORY = {"org": "acme", "repo": "repo-a", "ghsa": "GHSA-2222-3333-4444"}
DUP, OTHER = "GHSA-5555-6666-7777", "GHSA-8888-9999-cccc"


def test_badge():
    assert render.badge("same_bug", dedup.TONES) == "<span class='badge bad'>same_bug</span>"
    assert render.badge("mystery", dedup.TONES) == "<span class='badge none'>mystery</span>"
    assert render.badge(None, dedup.TONES) == "-"


def test_code_url():
    assert render.code_url(ADVISORY, "code/src/a.py") == "https://github.com/acme/repo-a/blob/HEAD/src/a.py"
    assert render.code_url(ADVISORY, "code/src/a.py:3") == "https://github.com/acme/repo-a/blob/HEAD/src/a.py#L3"
    assert render.code_url(ADVISORY, "code/a.py:71-80") == "https://github.com/acme/repo-a/blob/HEAD/a.py#L71-L80"
    assert render.code_url(ADVISORY, "not a ref") is None


def test_dedup_html_badges_links_and_escapes():
    result = {
        "relation": "same_bug",
        "duplicate_of": DUP,
        "fix_commit": "abc123",
        "evidence": ["code/src/export.py:71-80", "not a ref <x>"],
        "rejected": [{"ghsa_id": OTHER, "reason": "other <file>"}],
        "rationale": f"Same fix as {DUP}.",
    }
    html = dedup.html(result, ADVISORY)
    assert "<span class='badge bad'>same_bug</span>" in html
    assert (
        "<a href='https://github.com/acme/repo-a/blob/HEAD/src/export.py#L71-L80'>code/src/export.py:71-80</a>" in html
    )
    assert html.count(f"<a href='/{DUP}'>{DUP}</a>") == 2
    assert f"<a href='/{OTHER}'>" in html
    assert "<x>" not in html and "<file>" not in html
    assert dedup.cell(result) == f"<span class='badge bad'>same_bug</span> <a href='/{DUP}'>{DUP}</a>"


def test_legit_html_badges_each_step_and_escapes_claims():
    result = {
        "verdict": "uncertain",
        "threat_model": "documented",
        "threat_model_sources": ["code/SECURITY.md"],
        "attacker": "anyone",
        "gain": "RCE",
        "in_scope": "yes",
        "chain": "unverified",
        "steps": [
            {"claim": "a <b>bold</b> claim", "evidence": ["code/a.py:3"], "status": "holds"},
            {"claim": "second", "evidence": [], "status": "fails"},
        ],
        "open_questions": [f"Is {DUP} related?"],
        "rationale": "Unclear.",
    }
    html = legit.html(result, ADVISORY)
    for value, tone in [
        ("uncertain", "warn"),
        ("documented", "good"),
        ("yes", "good"),
        ("holds", "good"),
        ("fails", "bad"),
    ]:
        assert f"<span class='badge {tone}'>{value}</span>" in html
    assert "<a href='https://github.com/acme/repo-a/blob/HEAD/a.py#L3'>code/a.py:3</a>" in html
    assert "a &lt;b&gt;bold&lt;/b&gt; claim" in html
    assert f"<li>Is <a href='/{DUP}'>{DUP}</a> related?</li>" in html
    assert legit.cell(result) == "<span class='badge warn'>uncertain</span>"
