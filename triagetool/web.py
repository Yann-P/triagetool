"""The web pages and the http server. GET only."""

import json
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from triagetool import host, store
from triagetool.batch import TOOLS
from triagetool.render import badge, kv_table, linkify, table

STATES = ["published", "draft", "triage", "closed"]
TONES = {
    "critical": "bad",
    "high": "bad",
    "medium": "warn",
    "low": "note",
    "triage": "warn",
    "draft": "note",
    "published": "good",
    "error": "bad",
}
DATATABLES = "https://cdn.jsdelivr.net/npm/simple-datatables@10.3.0/dist"
STYLE = """
body { font-family: system-ui, sans-serif; line-height: 1.4; margin: 1em 2em; }
table { border-collapse: collapse; }
th, td { text-align: left; padding: 0.2em 0.8em; border-bottom: 1px solid #ddd; vertical-align: top; }
tbody tr:nth-child(even) { background: rgba(0, 0, 0, 0.04); }
tbody tr:hover { background: rgba(255, 220, 120, 0.3); }
pre { background: #f4f4f4; padding: 0.8em; overflow-x: auto; }
.refs { font-family: monospace; margin: 0; padding-left: 1.2em; }
.prose { max-width: 70ch; }
.badge { padding: 0.1em 0.5em; border-radius: 0.6em; white-space: nowrap; }
.bad { background: rgba(255, 120, 120, 0.35); }
.warn { background: rgba(255, 200, 90, 0.4); }
.good { background: rgba(120, 210, 140, 0.35); }
.note { background: rgba(120, 170, 255, 0.35); }
.error { color: #b00; }
"""


def page(title: str, body: str, head: str = "") -> str:
    head = f"<meta charset='utf-8'><title>{escape(title)}</title><style>{STYLE}</style>{head}"
    return f"<!doctype html><html><head>{head}</head><body><h1>{escape(title)}</h1>{body}</body></html>"


def github_url(advisory: dict) -> str:
    return f"https://github.com/{advisory['org']}/{advisory['repo']}/security/advisories/{advisory['ghsa']}"


def verdict_cell(name: str, verdict) -> str:
    """What the index shows for one tool: its short answer, error, or - when not run."""
    if verdict is None:
        return "-"
    if "error" in verdict:
        return badge("error", TONES)
    return TOOLS[name].cell(verdict["result"])


def index_row(advisory: dict) -> list:
    verdicts = store.load_verdicts(advisory["ghsa"])
    return [
        linkify(advisory["ghsa"]),
        badge(advisory["state"], TONES),
        badge(advisory["severity"], TONES),
        escape(f"{advisory['org']}/{advisory['repo']}"),
        escape(advisory["created"]),
        linkify(advisory["title"]),
    ] + [verdict_cell(name, verdicts.get(name)) for name in TOOLS]


def state_links(current: str) -> str:
    links = []
    for state in STATES + ["all"]:
        if state == current:
            links.append(f"<b>{state}</b>")
        else:
            links.append(f"<a href='/?state={state}'>{state}</a>")
    return " | ".join(links)


def index_page(data: dict, state: str) -> str:
    if not data["fetched_at"]:
        return page("Advisories", "<p>No advisories yet. Run: <code>triagetool batch repos.txt</code></p>")
    advisories = data["advisories"]
    if state != "all":
        advisories = [adv for adv in advisories if adv["state"] == state]
    body = (
        f"<p>{state_links(state)} &middot; fetched {escape(data['fetched_at'])}</p>"
        + table(
            ["ghsa", "state", "severity", "repo", "created", "title", *TOOLS], [index_row(adv) for adv in advisories]
        )
        + f"<script src='{DATATABLES}/umd/simple-datatables.js'></script>"
        + "<script>new simpleDatatables.DataTable('table', {perPage: 50, perPageSelect: [25, 50, 100, 250]})</script>"
    )
    return page("Advisories", body, f"<link rel='stylesheet' href='{DATATABLES}/style.css'>")


def verdict_section(name: str, advisory: dict, verdict) -> str:
    if verdict is None:
        return "<p>Not run yet. Run: <code>triagetool batch repos.txt</code></p>"
    when = f"<p>ran at {escape(verdict['ran_at'])}</p>"
    if "error" in verdict:
        return f"{when}<pre class='error'>{escape(verdict['error'])}</pre>"
    raw = escape(json.dumps(verdict["result"], indent=2))
    rendered = TOOLS[name].html(verdict["result"], advisory)
    return f"{when}{rendered}<details><summary>raw JSON</summary><pre>{raw}</pre></details>"


def advisory_page(advisory: dict) -> str:
    verdicts = store.load_verdicts(advisory["ghsa"])
    fields = [
        (key, badge(value, TONES) if key in ("state", "severity") else linkify(value))
        for key, value in advisory.items()
    ]
    body = f"<p><a href='/'>back</a> &middot; <a href='{escape(github_url(advisory))}'>open on GitHub</a></p>"
    body += kv_table(fields)
    for name in TOOLS:
        body += f"<h2>{name}</h2>" + verdict_section(name, advisory, verdicts.get(name))
    return page(advisory["ghsa"], body)


def find_advisory(data: dict, ghsa: str):
    return next((adv for adv in data["advisories"] if adv["ghsa"] == ghsa), None)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        data = store.load_advisories()
        if url.path == "/":
            state = parse_qs(url.query).get("state", ["triage"])[0]
            return self.send_html(200, index_page(data, state))
        ghsa = url.path.lstrip("/")
        advisory = find_advisory(data, ghsa) if host.GHSA_RE.fullmatch(ghsa) else None
        if advisory is None:
            return self.send_html(404, page("Not found", f"<p>No advisory at {escape(url.path)}</p>"))
        self.send_html(200, advisory_page(advisory))

    def send_html(self, status: int, html: str) -> None:
        body = html.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(port: int) -> None:
    ThreadingHTTPServer(("localhost", port), Handler).serve_forever()
