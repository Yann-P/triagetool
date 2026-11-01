"""HTML pieces shared by the tools and the web pages. Every value passes through escape here."""

from html import escape

from triagetool import host


def badge(value, tones: dict) -> str:
    """A colored word, or - when there is none. tones maps a word to a CSS class."""
    if not value:
        return "-"
    return f"<span class='badge {tones.get(value, 'none')}'>{escape(value)}</span>"


def linkify(text) -> str:
    """Escaped text, with every GHSA id linked to its own page."""
    return host.GHSA_RE.sub(lambda m: f"<a href='/{m[0]}'>{m[0]}</a>", escape(text))


def prose(text) -> str:
    return f"<p class='prose'>{linkify(text or '-')}</p>"


def code_url(advisory: dict, ref: str):
    """GitHub link for a ref like code/path/file.py:71 or :71-80, or None when ref is not one."""
    match = host.REF_RE.fullmatch(ref)
    if not match:
        return None
    path, start, end = match.groups()
    url = f"https://github.com/{advisory['org']}/{advisory['repo']}/blob/HEAD/{path}"
    if start:
        url += f"#L{start}" + (f"-L{end}" if end else "")
    return url


def ref_link(advisory: dict, ref: str) -> str:
    url = code_url(advisory, ref)
    if url is None:
        return escape(ref)
    return f"<a href='{escape(url)}'>{escape(ref)}</a>"


def refs(advisory: dict, items: list) -> str:
    if not items:
        return "-"
    return "<ul class='refs'>" + "".join(f"<li>{ref_link(advisory, ref)}</li>" for ref in items) + "</ul>"


def table(columns: list, rows: list) -> str:
    """rows is a list of lists of html cells."""
    head = "".join(f"<th>{escape(column)}</th>" for column in columns)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def kv_table(rows: list) -> str:
    """rows is a list of (label, html) pairs."""
    body = "".join(f"<tr><th>{escape(label)}</th><td>{html}</td></tr>" for label, html in rows)
    return f"<table><tbody>{body}</tbody></table>"
