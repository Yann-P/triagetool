"""The inbox: every report in triage with what the analysis found, as one web page."""

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from triagetool import host, pipeline, store, verdict
from triagetool.threatmodel import QUESTIONS
from triagetool.writeup import LENGTHS

# group -> heading, in the order shown
GROUPS = {
    "probably_real": "Probably real",
    "duplicate": "Probably a duplicate",
    "probably_invalid": "Probably not a vulnerability",
    "ask_reporter": "Worth asking the reporter",
    "unsure": "Could not tell",
    "todo": "Not analysed yet",
}
REAL = {
    "probably_real": "Probably",
    "probably_invalid": "Probably not",
    "ask_reporter": "Ask the reporter",
    "unsure": "Could not tell",
}
BOUNDARY = {
    "crossed": "This would give the attacker something the project is meant to keep from them.",
    "not_crossed": "The attacker's starting position already allows this.",
    "undocumented": "The project's docs do not say whether this is allowed.",
}
ZOOMS = {"tldr": "TL;DR", "short": "Short", "medium": "Medium", "full": "Full"}
STATES = {"triage": "still in triage", "draft": "a draft", "published": "published", "closed": "closed"}
MARKS = {"yes": "✓", "no": "✗", "unknown": "?"}
STYLE = (Path(__file__).parent / "inbox.css").read_text()
SCRIPT = (Path(__file__).parent / "inbox.js").read_text()

# one piece of analysis at a time: each one starts and stops the sandbox, and two would stop each other's
BACKGROUND = ThreadPoolExecutor(1)
# what the automatic check last did: a few words for the top row, and the reason when it failed
STATUS = {"text": "", "problem": ""}


def external(url: str, text: str) -> str:
    return f"<a href='{escape(url)}' target='_blank' rel='noopener'>{escape(text)}</a>"


def code_link(repo: str, reference: str) -> str:
    """A link to GitHub for a reference like code/path/file.py:71 or :71-80."""
    path, first_line, last_line = host.REFERENCE_RE.fullmatch(reference).groups()
    url = f"https://github.com/{repo}/blob/HEAD/{path}"
    if first_line:
        url += f"#L{first_line}"
    if last_line:
        url += f"-L{last_line}"
    return external(url, reference.removeprefix("code/"))


def button(action: str, label: str, fields: dict, explains: str = "", text_field: str = "") -> str:
    """A form that posts fields to action.

    explains says what the button does, shown when the pointer rests on it. With text_field, the user types one
    more field before sending, and explains is the hint shown inside it.
    """
    html = ""
    for name, value in fields.items():
        html += f"<input type='hidden' name='{name}' value='{escape(value)}'>"
    if text_field:
        html += f"<input name='{text_field}' placeholder='{escape(explains)}'>"
    return f"<form method='post' action='{action}'>{html}<button title='{escape(explains)}'>{label}</button></form>"


def load_advisories() -> dict:
    """ghsa -> every stored advisory, in every state, with its repository."""
    advisories = {}
    for repo in store.repos():
        for advisory in store.load(repo, "advisories")["advisories"]:
            advisories[advisory["ghsa"]] = {**advisory, "repo": repo}
    return advisories


def prose(text: str, advisories: dict) -> str:
    """Text an agent wrote, escaped, with every advisory id it mentions linked to GitHub."""

    def link(match):
        ghsa = match[0]
        if ghsa not in advisories:
            return ghsa
        return external(advisories[ghsa]["url"], ghsa)

    return host.GHSA_RE.sub(link, escape(text))


def age(day: str) -> str:
    """How long ago a day like 2026-11-04 was, in words."""
    days = (date.today() - date.fromisoformat(day)).days
    if days <= 0:
        return "today"
    if days == 1:
        return "1 day ago"
    return f"{days} days ago"


def track_record(reporter: str, advisories: dict) -> str:
    """What became of everything this person reported to the stored repositories."""
    states = [advisory["state"] for advisory in advisories.values() if advisory["reporter"] == reporter]
    return f"{len(states)} reports, {states.count('published')} accepted, {states.count('closed')} turned down"


def group(record: dict) -> str:
    """The key of GROUPS a report belongs under."""
    if "verdict" not in record:
        return "todo"
    if record["verdict"]["duplicate_of"]:
        return "duplicate"
    return verdict.decide(record["verdict"])


def assessed_severity(answer: dict) -> str:
    if verdict.decide(answer) == "probably_invalid":
        # how bad it would be if true is noise on a report that is probably not true
        return "none"
    return answer["severity"]


def facts(advisory: dict, answer: dict | None, advisories: dict) -> str:
    """The box of short facts beside the prose. answer is None for a report that has no analysis yet."""
    rows = []
    reported = advisory["severity"] or "none"
    if answer is not None:
        rows.append(("Is it real?", REAL[verdict.decide(answer)]))
        older = advisories.get(answer["duplicate_of"])
        if older is None:
            rows.append(("Seen before?", "No"))
        else:
            link = external(older["url"], older["ghsa"])
            rows.append(("Seen before?", f"Yes<br>{link}, {STATES[older['state']]}"))
        rows.append(("Assessed severity", assessed_severity(answer)))
    rows.append(("Reported severity", escape(reported)))
    reporter = advisory["reporter"]
    if reporter:
        profile = external(f"https://github.com/{reporter}", reporter)
        rows.append(("Reported by", f"{profile}<br>{track_record(reporter, advisories)}"))
    rows.append(("Advisory", external(advisory["url"], advisory["ghsa"])))
    rows.append(("Repository", escape(advisory["repo"])))
    rows.append(("Opened", f"{escape(advisory['created'])}, {age(advisory['created'])}"))
    html = ""
    for label, value in rows:
        html += f"<tr><th>{label}</th><td>{value}</td></tr>"
    return f"<table class='facts'>{html}</table>"


def section(label: str, html: str) -> str:
    """One labelled part of a card."""
    return f"<h4>{label}</h4>{html}"


def missing_docs(repo: str) -> list[str]:
    """The questions the repository's security docs leave unanswered. None when there is no audit of them yet."""
    audit = store.load(repo, "threatmodel").get("audit")
    if not audit:
        return []
    return [QUESTIONS[key] for key, check in audit["checks"].items() if check["status"] == "missing"]


def security_docs(repo: str) -> str:
    missing = missing_docs(repo)
    if not missing:
        return ""
    return section(
        "Security docs",
        f"<p>The docs of {escape(repo)} do not say: {escape(' '.join(missing))} "
        "Reports are easier to settle once they do.</p>",
    )


def actions(advisory: dict, record: dict) -> str:
    """The foot of an analysed card: what the maintainer can do about the report, in one place."""
    if "verdict" not in record:
        return ""
    ghsa = advisory["ghsa"]
    repo = advisory["repo"]
    row = ""
    if missing_docs(repo):
        explains = f"Reads the docs of {repo} again, then checks again the reports they could not settle."
        row = button("/reaudit", "Its docs were updated", {"repo": repo}, explains)
    explains = "Tell the checker what it missed, or leave empty for a fresh look"
    again = button("/recheck", "Check again", {"ghsa": ghsa}, explains, text_field="hint")
    chat = f"<code title='Run this in a terminal to talk the report through.'>triagetool chat {ghsa}</code>"
    return f"<footer>{again}<div class='row'>{row}{chat}</div></footer>"


def wordings(record: dict) -> dict:
    """level -> the prose parts of a card at that level.

    A level that has no write-up, on a record made before they existed or when the writer failed, gets the
    investigator's own words.
    """
    answer = record["verdict"]
    own_words = {
        "finding": f"{answer['headline']} {answer['why']}",
        "attacker": answer["attacker_needs"],
        "facts": [link["fact"] for link in answer["links"]],
        "severity": answer["severity_why"],
        "ask": answer["ask"],
    }
    texts = record.get("texts", {})
    by_level = {}
    for level in LENGTHS:
        by_level[level] = {**own_words, **texts.get(level, {})}
    if "tldr" not in texts:
        by_level["tldr"]["finding"] = answer["headline"]
    return by_level


def zoomed(texts: dict, advisories: dict) -> str:
    """One piece of prose at every level. texts is level -> text, and the stylesheet shows the level zoomed to."""
    html = ""
    for level, text in texts.items():
        html += f"<span data-text='{level}'>{prose(text, advisories)}</span>"
    return html


def analysis(advisory: dict, record: dict, advisories: dict) -> str:
    """Below the title: everything that was found, the error, or where the analysis stands."""
    repo = advisory["repo"]
    if "verdict" not in record:
        error = record.get("error") or store.load(repo, "threatmodel").get("error")
        if error:
            again = button("/recheck", "Try again", {"ghsa": advisory["ghsa"]})
            return section("The analysis failed", f"<pre>{escape(error[-1500:])}</pre>{again}")
        if "previous" in record:
            return "<p class='quiet'>Being checked again. Reload in a few minutes.</p>"
        return "<p class='quiet'>Not analysed yet.</p>"
    answer = record["verdict"]
    by_level = wordings(record)

    def part(name: str) -> str:
        return zoomed({level: parts[name] for level, parts in by_level.items()}, advisories)

    html = f"<p class='finding'>{part('finding')}</p>"
    if answer["ask"]:
        html += section("Ask the reporter", f"<p>{part('ask')}</p>")
    if record.get("hint"):
        html += section("Checked again after you said", f"<p>{escape(record['hint'])}</p>")
    links = ""
    for index, link in enumerate(answer["links"]):
        source = ""
        if link["where"]:
            source = code_link(repo, link["where"])
        fact = zoomed({level: parts["facts"][index] for level, parts in by_level.items()}, advisories)
        links += f"<li><span class='mark'>{MARKS[link['holds']]}</span><div>{fact}<div class='source'>{source}</div></div></li>"
    return (
        html
        + section("The report claims", f"<p>{prose(record['claim']['summary'], advisories)}</p>")
        + section("The attacker needs", f"<p>{part('attacker')} {BOUNDARY[answer['boundary']]}</p>")
        + section("What the report needs to be true", f"<ul class='links'>{links}</ul>")
        + section("Severity", f"<p>{part('severity')}</p>")
        + security_docs(repo)
    )


def card(advisory: dict, record: dict, advisories: dict) -> str:
    searched = f"{advisory['title']} {advisory['repo']} {advisory['reporter']} {advisory['ghsa']}".lower()
    return (
        f"<article id='{advisory['ghsa']}' class='{group(record)}' data-level='medium' "
        f"data-seen='{advisory['ghsa']} {group(record)}' "
        f"data-repo='{escape(advisory['repo'])}' data-search='{escape(searched)}' data-url='{escape(advisory['url'])}'>"
        "<div class='main'>"
        f"<h3>{external(advisory['url'], advisory['title'])}</h3>"
        f"{analysis(advisory, record, advisories)}"
        f"{actions(advisory, record)}"
        "</div>"
        f"{facts(advisory, record.get('verdict'), advisories)}"
        "</article>"
    )


def bar(count: int, advisories: dict) -> str:
    """The one row that stays at the top: the count, sync, the repository filter, search, and the keys."""
    repos = sorted({advisory["repo"] for advisory in advisories.values() if advisory["state"] == "triage"})
    options = "<option value=''>Every repository</option>"
    for repo in repos:
        options += f"<option>{escape(repo)}</option>"
    return (
        "<header>"
        "<div class='bar'>"
        "<button type='button' id='show-contents'>List</button>"
        f"<strong>{count} in triage</strong>"
        f"<span class='quiet'>{escape(STATUS['text'])}</span>"
        "<a class='quiet' id='reload' href='/' hidden>new results, reload</a>"
        f"{button('/sync', 'Sync', {})}"
        f"<select id='repo'>{options}</select>"
        "<input id='search' type='search' placeholder='Search'>"
        "<button type='button' id='help'>?</button>"
        "</div>"
        f"<p class='problem'>{escape(STATUS['problem'])}</p>"
        "<p class='quiet' id='keys' hidden>j and k move between reports · o opens one on GitHub · "
        "- and + zoom every report out and in, from one paragraph to the full wording · "
        "Enter zooms the selected report alone · a click selects a report · / searches · ? shows this</p>"
        "</header>"
    )


def state(advisories: dict) -> str:
    """A short text that changes whenever a report enters, leaves, or moves to another group."""
    lines = []
    for advisory in advisories.values():
        if advisory["state"] == "triage":
            record = store.load(advisory["repo"], advisory["ghsa"])
            lines.append(f"{advisory['ghsa']} {group(record)}")
    return hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()


def sections(in_triage: list) -> dict:
    """heading -> the reports under it, newest first. The page and the list on the left both follow this.

    in_triage holds (advisory, record) pairs.
    """
    newest_first = sorted(in_triage, key=lambda pair: pair[0]["created"], reverse=True)
    by_verdict = {}
    for key, heading in GROUPS.items():
        under = [pair for pair in newest_first if group(pair[1]) == key]
        if under:
            by_verdict[heading] = under
    return by_verdict


def contents(sectioned: dict) -> str:
    """The list on the left: one line per report, under the same headings and in the same order as the page."""
    html = ""
    for heading, under in sectioned.items():
        html += f"<div class='part'><h6>{escape(heading)}</h6>"
        for advisory, record in under:
            title = escape(advisory["title"])
            html += f"<a class='{group(record)}' href='#{advisory['ghsa']}' title='{title}'>{title}</a>"
        html += "</div>"
    return f"<nav id='contents'>{html}</nav>"


def zoom() -> str:
    """The zoom levels, in the margin right of the page."""
    levels = ""
    for level, label in ZOOMS.items():
        levels += f"<button type='button' data-set-level='{level}'>{label}</button>"
    return f"<nav id='zoom'><h6>Zoom</h6>{levels}</nav>"


def inbox() -> str:
    advisories = load_advisories()
    in_triage = []
    for advisory in advisories.values():
        if advisory["state"] == "triage":
            in_triage.append((advisory, store.load(advisory["repo"], advisory["ghsa"])))
    sectioned = sections(in_triage)
    body = bar(len(in_triage), advisories)
    if not advisories:
        body += "<p>Nothing here yet. Run: <code>triagetool run repos.txt</code></p>"
    for heading, under in sectioned.items():
        cards = "".join(card(advisory, record, advisories) for advisory, record in under)
        count_note = f"<span class='quiet'>{len(under)}</span>"
        body += f"<section><h2>{escape(heading)} {count_note}</h2>{cards}</section>"
    body = f"{contents(sectioned)}{zoom()}<main>{body}</main><script>{SCRIPT}</script>"
    head = f"<meta charset='utf-8'><title>Triage inbox</title><style>{STYLE}</style>"
    return f"<!doctype html><html><head>{head}</head><body data-state='{state(advisories)}'>{body}</body></html>"


def set_aside(repo: str, ghsa: str, hint: str) -> None:
    """Make a stored record one that gets checked again: its verdict becomes the previous one, its error goes."""
    record = store.load(repo, ghsa)
    if "verdict" in record:
        store.save(repo, ghsa, {"claim": record["claim"], "previous": record["verdict"], "hint": hint})
    elif "error" in record:
        del record["error"]
        store.save(repo, ghsa, record)


def recheck(fields: dict, options) -> str:
    """Send the checker back to one report, with what the maintainer said about its answer."""
    ghsa = host.ghsa_id(fields["ghsa"])
    repo = load_advisories()[ghsa]["repo"]
    set_aside(repo, ghsa, fields.get("hint", "").strip()[: host.MAX_TEXT])
    BACKGROUND.submit(pipeline.look_again, repo, [ghsa], False, options.since, options.jobs)
    return ghsa


def reaudit(fields: dict, options) -> str:
    """Read a repository's security docs again, then check again the reports its docs could not settle."""
    repo = host.repo_name(fields["repo"])
    undecided = []
    for advisory in load_advisories().values():
        if advisory["repo"] != repo or advisory["state"] != "triage":
            continue
        answer = store.load(repo, advisory["ghsa"]).get("verdict")
        if answer and answer["boundary"] == "undocumented":
            set_aside(repo, advisory["ghsa"], "The project's security docs changed. Read threatmodel.json again.")
            undecided.append(advisory["ghsa"])
    BACKGROUND.submit(pipeline.look_again, repo, undecided, True, options.since, options.jobs)
    return ""


def sync(fields: dict, options) -> str:
    """Fetch the advisories again, so the ones that left triage leave the page."""
    pipeline.sync(store.repos())
    return ""


# path -> what a button on the page does. Each returns the id of the card to come back to, or "".
ACTIONS = {"/sync": sync, "/recheck": recheck, "/reaudit": reaudit}


class Handler(BaseHTTPRequestHandler):
    options = None

    def do_GET(self):
        if self.path == "/":
            body = inbox().encode()
        elif self.path == "/state":
            body = state(load_advisories()).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.headers.get("Origin") != f"http://{self.headers.get('Host')}":
            # another site made the browser send this
            self.send_error(403)
            return
        if self.path not in ACTIONS:
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        sent = parse_qs(self.rfile.read(length).decode())
        fields = {name: values[0] for name, values in sent.items()}
        card_id = ACTIONS[self.path](fields, self.options)
        self.send_response(303)
        # with no card to point at, the browser keeps the report the address already named
        self.send_header("Location", f"/#{card_id}" if card_id else "/")
        self.end_headers()


def check(options) -> None:
    """One automatic round: fetch the advisories and analyse the reports that have no verdict yet.

    What failed in an earlier round is not tried again, so that a report that always fails does not cost a run
    every few minutes. The Try again button on its card does that.
    """
    STATUS["text"] = "checking now"
    now = datetime.now().strftime("%H:%M")
    try:
        repos = pipeline.read_repos(options.repos) or store.repos()
        pipeline.run(repos, options.since, False, options.jobs, retry_errors=False)
        STATUS["text"] = f"checked {now}"
        STATUS["problem"] = ""
    except host.ToolError as error:
        reason = str(error).strip().splitlines()[-1]
        STATUS["text"] = f"check failed {now}"
        STATUS["problem"] = f"The automatic check failed: {reason}"


def keep_watch(options) -> None:
    while True:
        BACKGROUND.submit(check, options).result()
        time.sleep(options.every * 60)


def serve(args) -> None:
    host.stop_on_interrupt()
    Handler.options = args
    if args.every > 0:
        threading.Thread(target=keep_watch, args=[args], daemon=True).start()
    print(f"http://localhost:{args.port}/", flush=True)
    ThreadingHTTPServer(("localhost", args.port), Handler).serve_forever()
