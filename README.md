# triagetool

A triage inbox for GitHub Security Advisories. It reads every report waiting in triage across your repositories, checks each one against the code with an LLM, and tells you in plain English what it comes down to.

⛔ **DO NOT OUTSOURCE YOUR JUDGEMENT TO AN AI.** The verdicts are hints for where to look first. You make the call.

## Why not just ask an LLM

An LLM that reads a long, confident, AI-written report tends to agree with it. So here the model that checks the code never sees the report:

1. A **clerk** reads the report and restates it as a short neutral claim: who the attacker is, what they do, what they gain, in at most six steps. Severity, scores, adjectives and arguments are dropped. A one-line report and a ten-page one produce a claim of the same size. The clerk has no code and no tools.
2. A **checker** gets the claim, the code, and what the project's docs say about its security boundary. It breaks the claim into the few facts it cannot do without, and marks each one as found in the code, contradicted by it, or unknown.
3. **The verdict is computed from those facts.** The model chooses which facts to check and whether a boundary is crossed, and has to commit to each one. It cannot hand out a verdict that its own facts do not support. A fact marked as found counts only when it points at a file that exists.

| The checker found | Verdict |
|---|---|
| a fact the code contradicts, or the attacker already had what they gain | probably not a vulnerability |
| every fact in the code, and a boundary crossed | probably real |
| open facts, and one question that would settle them | needs an answer from the reporter |
| anything else | could not tell |

Whether a report repeats an older advisory is a separate answer. A duplicate still says whether it looks real.

The checker also rates the severity itself, from the attacker's starting position and what they end up with. The inbox shows it next to the one the reporter picked.

Everything runs in a Docker sandbox with no internet and no access to your machine, see [SECURITY.md](SECURITY.md).

## Install

```
pipx install git+https://github.com/Yann-P/triagetool
# or,
uv tool install git+https://github.com/Yann-P/triagetool
```

You need:

- `gh` (GitHub CLI), logged in
- Docker with Compose, running
- either `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` in your env

## Every day

```
triagetool serve repos.txt
```

Leave it running and keep http://localhost:8000/ open in a tab. Every 15 minutes it fetches the advisories of your repositories and analyses the reports in triage that have no verdict yet, four at a time. The tab's title says how many reports are new since you last looked, and the page tells you when fresh results are in. `--every` changes the pace and `--jobs` the number of agents running at once.

A report is paid for once. One that failed is not tried again by itself, so that a report that always fails does not cost a run every 15 minutes: its card shows the error and a **Try again** button.

`repos.txt` holds one `owner/name` per line. Blank lines and `#` comments are ignored. You can also name repositories directly, and after the first time you can leave them out: `serve` then watches every repository it already knows. If you deal with many organizations, [github-security-overview](https://github.com/Yann-P/github-security-overview) can write the file for you:

```
security-overview "${JUPYTER_ORGS[@]}" --columns org,repo | sort -u > repos.txt
```

To do one round by hand, or from a scheduler, without the web page:

```
triagetool run repos.txt
```

`run` also tries again what failed before, and `--force` redoes everything.

`serve` shows the inbox at http://localhost:8000/. Reports are grouped by verdict. In the left margin, a quiet list names every report under the same headings and in the same order, and a click there jumps to it. In the right margin are the zoom levels. The address in the browser remembers the report you are on. The bar at the top filters reports by repository and searches titles, repositories, reporters and ids. The search forgives missing letters, so `nbfrmt` finds `nbformat`.

Every report always shows all of its parts: what it comes down to, a box of facts beside it (whether it looks real, whether it was seen before and what became of that older advisory, the assessed and the reported severity, who reported it and what became of their earlier reports), the claim, what the attacker needs, each checked fact with a link to the line of code, the reason for the severity, and what the repository's security docs fail to say.

What changes is how it is worded. Once a report is investigated, a writer turns the findings into four write-ups, each from its own instructions, like asking someone to be brief or to be thorough:

- **TL;DR**: the report collapses to its title and one short paragraph that says it all in one breath.
- **Short**: for a colleague who asks in passing and has ten seconds.
- **Medium**: for one who stopped at your desk and has a minute.
- **Full**: for one who is about to act and must not be surprised later.

You zoom between them. They all say the same thing, because they are written from the same findings, and all are in plain everyday English.

| Key | Does |
|---|---|
| `j` `k` | move to the next or the previous report |
| `-` `+` | zoom every report out or in |
| `Enter` | zoom the selected report alone, one step in, and back out after full |
| `o` | open it on GitHub |
| `/` | search |
| `?` | show these keys on the page |

When the wording is not to your taste, change the instructions in `triagetool/writeup.py` and run `triagetool run repos.txt --rewrite`. It writes the write-ups again and keeps the verdicts, so nothing is investigated twice.

The title of a report opens the advisory on GitHub, as does every advisory id on the page.

### You steer it

- **Check again.** Tell the checker what it missed and send it back. It takes what you say as a strong lead and still verifies it in the code. Leave the box empty for a fresh look.
- **Its docs were updated.** When many reports of a repository end in "could not tell" because its docs do not say where the boundary is, write that down in the repository's `SECURITY.md`. Then use this button: the docs are audited again, and the reports they could not settle are checked again.
- **Sync with GitHub** fetches the advisory states again, so the reports you closed or published leave the page. It runs no analysis and takes a few seconds.

Checking again runs in the background, one request at a time, and the page says so until it is done. `serve` needs Docker and the token, like `run`. When either is missing, the page says so under the search bar.

## Dig into one report

```
triagetool chat GHSA-xxxx-xxxx-xxxx
```

Opens Claude Code inside the sandbox with the repository cloned, the report, the claim, the verdict, the threat model audit and the other advisories loaded. Unlike the checker, this session does read the original report.

## Audit a repository's security docs

```
triagetool threatmodel owner/name
```

A report can only be called out of scope when the docs say where the boundary is. This asks seven questions of a repository's docs: who is trusted, what an attacker may control, what the project promises to protect, what is not a vulnerability, what an operator must do, how to report, and which versions get fixes. Each is `answered`, `partial` or `missing`, with a pointer and a note on what to write down.

`run` does this once per repository and hands the result to the checker, so every report of a repository is judged against the same boundary. The standalone command needs no advisory and works on any repository you can read.

Only the files in the repository are read. A `SECURITY.md` inherited from the organization's `.github` repository is not seen.

## What is stored

Everything lives under `data/` in the directory you run the commands from, one folder per repository:

- `data/repos/<owner>/<name>/advisories.json` lists its advisories, in every state
- `data/repos/<owner>/<name>/threatmodel.json` is the audit of its security docs
- `data/repos/<owner>/<name>/<GHSA>.json` is the claim and the verdict for one report

Delete a file to forget it.

## AI Disclosure

This repository was created with assistance from Claude.
