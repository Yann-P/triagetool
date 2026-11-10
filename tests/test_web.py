from triagetool import host, store, web

from .conftest import FIRST_ID, SECOND_ID, THIRD_ID, advisory

VERDICT = {
    "headline": "Needs <admin> rights already.",
    "why": "Only an admin can reach it.",
    "full": "The upload page is behind the admin login. Step by step, nothing else is open.",
    "attacker_needs": "An admin account.",
    "boundary": "not_crossed",
    "links": [
        {"fact": "The upload is not checked.", "holds": "yes", "where": "code/src/a.py:71-80"},
        {"fact": "Anyone can upload.", "holds": "no", "where": None},
    ],
    "duplicate_of": None,
    "severity": "low",
    "severity_why": "An admin is needed.",
    "ask": "",
}
UNSETTLED = {
    **VERDICT,
    "boundary": "undocumented",
    "links": [{"fact": "The upload is not checked.", "holds": "yes", "where": "code/src/a.py:71-80"}],
}
AUDIT = {
    "rating": "partial",
    "checks": {
        "trusted": {"status": "answered", "where": ["code/SECURITY.md"], "note": "n"},
        "attacker": {"status": "missing", "where": [], "note": "n"},
    },
}


def save_repo(*advisories):
    store.save("acme/app", "advisories", {"advisories": [host.summary(report) for report in advisories]})


def test_empty_inbox_says_how_to_start():
    assert "triagetool run repos.txt" in web.inbox()


def test_card_links_to_github_and_reads_in_plain_words():
    save_repo(advisory(FIRST_ID), advisory(SECOND_ID, "closed"), advisory(THIRD_ID, "published"))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "Upload <x> runs code."}, "verdict": VERDICT})
    store.save("acme/app", "threatmodel", {"audit": AUDIT})
    html = web.inbox()

    assert "<strong>1 in triage</strong>" in html
    assert "<h2>Probably not a vulnerability <span class='quiet'>1</span></h2>" in html
    assert "<option>acme/app</option>" in html
    assert f"data-repo='acme/app' data-search='path traversal in export acme/app mallory {FIRST_ID.lower()}'" in html
    assert f"<a href='https://github.com/acme/app/security/advisories/{FIRST_ID}' target='_blank'" in html
    assert f"href='/{FIRST_ID}'" not in html
    assert "Needs &lt;admin&gt; rights already." in html and "Upload &lt;x&gt; runs code." in html
    assert "<th>Is it real?</th><td>Probably not</td>" in html
    assert "<th>Seen before?</th><td>No</td>" in html
    assert (
        "<a href='https://github.com/mallory' target='_blank' rel='noopener'>mallory</a><br>3 reports, 1 accepted, 1 turned down</td>"
        in html
    )
    assert "<a href='https://github.com/acme/app/blob/HEAD/src/a.py#L71-L80'" in html
    assert "The attacker's starting position already allows this." in html
    assert (
        "<h4>Security docs</h4><p>The docs of acme/app do not say: What may an attacker control? Reports are easier"
        in html
    )
    assert ">Its docs were updated</button>" in html
    assert f"triagetool chat {FIRST_ID}" in html


def test_duplicate_links_to_the_older_advisory_on_github():
    save_repo(advisory(FIRST_ID), advisory(SECOND_ID, "published"))
    store.save(
        "acme/app",
        FIRST_ID,
        {"claim": {"summary": "s"}, "verdict": {**VERDICT, "duplicate_of": SECOND_ID}},
    )
    html = web.inbox()
    assert "<h2>Probably a duplicate <span class='quiet'>1</span></h2>" in html
    older = f"<a href='https://github.com/acme/app/security/advisories/{SECOND_ID}' target='_blank' rel='noopener'>"
    assert f"Yes<br>{older}{SECOND_ID}</a>, published" in html
    assert "<th>Is it real?</th><td>Probably not</td>" in html, "a duplicate still says if it is real"


def test_unanalysed_report_shows_why():
    save_repo(advisory(FIRST_ID), advisory(SECOND_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "error": "rejected: <no>"})
    html = web.inbox()
    assert "<h2>Not analysed yet <span class='quiet'>2</span></h2>" in html
    assert "<h4>The analysis failed</h4><pre>rejected: &lt;no&gt;</pre>" in html

    store.save("acme/app", "threatmodel", {"error": "audit failed"})
    assert "<pre>audit failed</pre>" in web.inbox()


def test_every_advisory_id_on_the_page_opens_github():
    save_repo(advisory(FIRST_ID), advisory(SECOND_ID, "closed"))
    told = {**VERDICT, "why": f"The same idea as {SECOND_ID}, and unlike GHSA-cccc-cccc-cccc."}
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": told})
    html = web.inbox()
    for ghsa in (FIRST_ID, SECOND_ID):
        link = f"<a href='https://github.com/acme/app/security/advisories/{ghsa}' target='_blank' rel='noopener'>{ghsa}</a>"
        assert link in html
    assert "unlike GHSA-cccc-cccc-cccc." in html


def test_assessed_severity_is_none_when_the_report_is_probably_invalid():
    save_repo(advisory(FIRST_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})
    html = web.inbox()
    assert "<th>Assessed severity</th><td>none</td>" in html
    assert "<th>Reported severity</th><td>critical</td>" in html

    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": UNSETTLED})
    html = web.inbox()
    assert "<th>Assessed severity</th><td>low</td>" in html
    assert "<h4>Severity</h4><p><span data-text='tldr'>An admin is needed.</span>" in html


class Options:
    since = "1 year ago"
    jobs = 2


def written(level):
    return {
        "finding": f"{level} finding",
        "attacker": f"{level} attacker",
        "facts": [f"{level} first fact", f"{level} second <fact>"],
        "severity": f"{level} severity",
        "ask": "",
    }


def test_zooming_changes_the_wording_and_never_what_is_shown():
    save_repo(advisory(FIRST_ID))
    texts = {level: written(level) for level in ("short", "medium", "full")}
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT, "texts": texts})
    html = web.inbox()
    for level in ("short", "medium", "full"):
        assert f"<span data-text='{level}'>{level} finding</span>" in html
        assert f"<span data-text='{level}'>{level} attacker</span>" in html
        assert f"<span data-text='{level}'>{level} second &lt;fact&gt;</span>" in html
        assert f"<span data-text='{level}'>{level} severity</span>" in html
    assert "<table class='facts'>" in html and "class='medium'" not in html and "<details" not in html


def test_a_level_without_a_write_up_shows_the_investigators_own_words():
    save_repo(advisory(FIRST_ID))
    texts = {"short": written("short")}
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT, "texts": texts})
    html = web.inbox()
    assert "<span data-text='short'>short finding</span>" in html
    own_words = "Needs &lt;admin&gt; rights already. Only an admin can reach it."
    assert f"<span data-text='medium'>{own_words}</span>" in html
    assert f"<span data-text='full'>{own_words}</span>" in html


def test_check_again_sets_the_answer_aside_with_the_hint(monkeypatch):
    started = []
    monkeypatch.setattr(web.BACKGROUND, "submit", lambda *job: started.append(job[1:]))
    save_repo(advisory(FIRST_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})

    assert web.recheck({"ghsa": FIRST_ID, "hint": " it needs <admin> "}, Options) == FIRST_ID

    record = store.load("acme/app", FIRST_ID)
    assert record["previous"] == VERDICT and record["hint"] == "it needs <admin>" and "verdict" not in record
    assert started == [("acme/app", [FIRST_ID], False, "1 year ago", 2)]
    assert "Being checked again." in web.inbox()

    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT, "hint": "it needs <admin>"})
    assert "<h4>Checked again after you said</h4><p>it needs &lt;admin&gt;</p>" in web.inbox()


def test_reading_the_docs_again_rechecks_only_what_the_docs_could_not_settle(monkeypatch):
    started = []
    monkeypatch.setattr(web.BACKGROUND, "submit", lambda *job: started.append(job[1:]))
    save_repo(advisory(FIRST_ID), advisory(SECOND_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})
    store.save("acme/app", SECOND_ID, {"claim": {"summary": "s"}, "verdict": UNSETTLED})

    web.reaudit({"repo": "acme/app"}, Options)

    assert started == [("acme/app", [SECOND_ID], True, "1 year ago", 2)]
    assert "verdict" in store.load("acme/app", FIRST_ID)
    assert store.load("acme/app", SECOND_ID)["previous"] == UNSETTLED


def test_a_failed_report_can_be_tried_again(monkeypatch):
    started = []
    monkeypatch.setattr(web.BACKGROUND, "submit", lambda *job: started.append(job[1:]))
    save_repo(advisory(FIRST_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "error": "agent failed"})
    assert ">Try again</button>" in web.inbox()

    web.recheck({"ghsa": FIRST_ID}, Options)
    assert store.load("acme/app", FIRST_ID).get("error") is None
    assert started == [("acme/app", [FIRST_ID], False, "1 year ago", 2)]


def test_the_page_state_changes_when_a_report_moves():
    save_repo(advisory(FIRST_ID))
    before = web.state(web.load_advisories())
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})
    after = web.state(web.load_advisories())
    assert before != after and f"data-state='{after}'" in web.inbox()


def test_an_automatic_check_says_how_it_went(monkeypatch):
    class Watching(Options):
        repos = ()

    asked = []
    monkeypatch.setattr(web.pipeline, "run", lambda *arguments, **named: asked.append((arguments, named)))
    save_repo(advisory(FIRST_ID))
    web.check(Watching)
    assert asked == [((["acme/app"], "1 year ago", False, 2), {"retry_errors": False})]
    assert web.STATUS["text"].startswith("checked ") and web.STATUS["problem"] == ""

    def no_docker(*arguments, **named):
        raise web.host.ToolError("lots of output\ndocker exited 1")

    monkeypatch.setattr(web.pipeline, "run", no_docker)
    web.check(Watching)
    assert web.STATUS["text"].startswith("check failed ")
    assert "<p class='problem'>The automatic check failed: docker exited 1</p>" in web.inbox()
    monkeypatch.setitem(web.STATUS, "problem", "")
    monkeypatch.setitem(web.STATUS, "text", "")


def headings(html, start, end, tag):
    part = html[html.index(start) : html.index(end)]
    return [piece.split("<")[0].strip() for piece in part.split(f"<{tag}>")[1:]]


def test_the_page_and_the_list_on_the_left_share_one_order():
    for repo, ghsa in [("acme-labs/app", FIRST_ID), ("acme/web", SECOND_ID), ("acme/api", THIRD_ID)]:
        summary = host.summary(advisory(ghsa))
        store.save(repo, "advisories", {"advisories": [{**summary, "title": f"Report on <{repo}>"}]})
    store.save("acme-labs/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})

    html = web.inbox()
    by_verdict = ["Probably not a vulnerability", "Not analysed yet"]
    assert headings(html, "<nav id='contents'>", "</nav>", "h6") == by_verdict
    assert headings(html, "<main>", "</main>", "h2") == by_verdict
    link = f"<a class='todo' href='#{THIRD_ID}' title='Report on &lt;acme/api&gt;'>Report on &lt;acme/api&gt;</a>"
    assert link in html


def test_reports_are_listed_newest_first():
    older = {**advisory(FIRST_ID), "created_at": "2026-09-01T10:00:00Z"}
    save_repo(older, advisory(SECOND_ID))
    html = web.inbox()
    assert html.index(f"<article id='{SECOND_ID}'") < html.index(f"<article id='{FIRST_ID}'")
    assert html.index(f"href='#{SECOND_ID}'") < html.index(f"href='#{FIRST_ID}'")


def test_the_tldr_is_one_paragraph_with_the_headline_until_it_is_written():
    save_repo(advisory(FIRST_ID))
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT})
    html = web.inbox()
    assert "<button type='button' data-set-level='tldr'>TL;DR</button>" in html
    assert "<p class='finding'><span data-text='tldr'>Needs &lt;admin&gt; rights already.</span>" in html

    texts = {"tldr": {"finding": "Probably not real, since only an admin can reach it."}}
    store.save("acme/app", FIRST_ID, {"claim": {"summary": "s"}, "verdict": VERDICT, "texts": texts})
    assert "<span data-text='tldr'>Probably not real, since only an admin can reach it.</span>" in web.inbox()


def luminance(color):
    digits = color.lstrip("#")
    if len(digits) == 3:
        digits = "".join(digit * 2 for digit in digits)
    channels = []
    for start in (0, 2, 4):
        value = int(digits[start : start + 2], 16) / 255
        channels.append(value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast(color, background):
    lighter, darker = sorted([luminance(color), luminance(background)], reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def test_every_text_color_is_readable_on_every_background_it_sits_on():
    import re

    text_colors = set(re.findall(r"(?<![-\w])color: (#[0-9a-fA-F]{3,6})", web.STYLE))
    assert "#6b6b6b" in text_colors, "the quiet grey of the side lists is among the colors checked"
    backgrounds = ["#ffffff", "#f4f4f4"]  # the page, an error box
    for color in text_colors:
        for background in backgrounds:
            assert contrast(color, background) >= 4.5, f"{color} on {background}"
    edges = set(re.findall(r"border: 1px solid (#[0-9a-fA-F]{3,6}); border-radius: 6px", web.STYLE))
    for edge in edges:
        assert contrast(edge, "#ffffff") >= 3, f"the edge of a button or a field, {edge}"


def test_the_opening_day_says_how_long_ago_it_was():
    from datetime import date, timedelta

    today = date.today()
    assert web.age(today.isoformat()) == "today"
    assert web.age((today - timedelta(days=1)).isoformat()) == "1 day ago"
    assert web.age((today - timedelta(days=6)).isoformat()) == "6 days ago"
    save_repo(advisory(FIRST_ID))
    days = (today - date(2026, 10, 1)).days
    assert f"<th>Opened</th><td>2026-10-01, {days} days ago</td>" in web.inbox()
