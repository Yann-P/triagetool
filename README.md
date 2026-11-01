# triagetool

Tools to assist in triaging GitHub Security Advisories using a LLM. Evaluation happens in a Docker sandbox with no internet or machine file access, see SECURITY.md.

⛔ **DO NOT OUTSOURCE YOUR JUDGEMENT TO AN AI.** DO NOT RELY SOLELY ON THIS TOOL'S OUTPUT. USE IT AS A HINT THAT A REPORT IS *PROBABLY* A DUPLICATE OR *PROBABLY* INVALID.

## Install

```
pipx install git+https://github.com/Yann-P/triagetool
# or,
uv tool install git+https://github.com/Yann-P/triagetool
```

## Prerequisites

- `gh` (GitHub CLI), logged in
- Docker with Compose
- either `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` in your env.


## 🔧 `dedup`

Checks whether an advisory is a duplicate of an older one in the same repository.

```
triagetool dedup jupyter/myrepository GHSA-xxxx-xxxx-xxxx
```

```json
{
  "relation": "same_bug",
  "duplicate_of": "GHSA-yyyy-yyyy-yyyy",
  "fix_commit": "ce4bd99",
  "evidence": ["code/myrepository/writers/files.py:71"],
  "rejected": [{"ghsa_id": "GHSA-zzzz-zzzz-zzzz", "reason": "same area, different sink"}],
  "rationale": "..."
}
```

- `relation` is one of `same_bug` (same root cause, same code path), `same_root_cause` (same mistake, different code path), `related`, or `distinct`. 
- `duplicate_of` names the oldest advisory for that bug, preferring a published one.
- `rejected` are duplicate candidates that were assessed.


## 🔧 `legit`

Checks whether an advisory describes a real vulnerability.

```
triagetool legit jupyter/myrepository GHSA-xxxx-xxxx-xxxx
```

```json
{
  "verdict": "uncertain",
  "threat_model": "missing",
  "threat_model_sources": [],
  "attacker": "Someone who ships a notebook the victim converts",
  "gain": "Writes any file the victim can write",
  "in_scope": "unclear",
  "chain": "complete",
  "steps": [
    {"claim": "The notebook sets an output filename with ../", "evidence": [], "status": "holds"},
    {"claim": "The filename reaches os.path.join unchanged", "evidence": ["code/myrepository/writers/files.py:71"], "status": "holds"}
  ],
  "open_questions": ["Are notebooks from strangers in scope? Nothing in the repo says."],
  "rationale": "..."
}
```

- `threat_model` is how well the repository documents its security boundary. **This is very important to triage effectively. If it is weak or missing, treat the rest with a grain of salt and go document that threat model.**
- `attacker`, `gain` and `in_scope` describe what the attacker can already do, what the exploit would add, and whether that crosses the documented boundary. If the attacker already has the gain, the report is out of scope.
- `chain` is the exploit written as steps from attacker-controlled input to the claimed gain. Each step is checked against the code and marked as holding, failing, or unverified.

## 🔧 `batch`

Runs `dedup` and `legit` on every advisory in triage of each repository listed in a file, and keeps every verdict on disk so no advisory is paid for twice.

```
triagetool batch repos.txt
```

`repos.txt` holds one `owner/name` per line. Blank lines and `#` comments are ignored. If you deal with many organizations, [github-security-overview](https://github.com/Yann-P/github-security-overview) can write it for you:

```
security-overview "${JUPYTER_ORGS[@]}" --columns org,repo | sort -u > repos.txt
```

Each repository is fetched and cloned once, then every advisory in triage goes through every tool. A pair that already has a stored result is skipped, a stored error is tried again, and `--force` runs everything again. Every verdict is saved as soon as it is ready, so you can stop the batch and start it again later. `--since` works as in the one-shot commands.

Everything lives under `data/` in the directory you run the commands from:

- `data/advisories.json` lists every advisory of those repositories, in every state
- `data/verdicts/<GHSA>.<tool>.json` is one verdict

Delete a verdict file to forget it.

## 🔧 `serve`

Shows the advisories and their verdicts in a web page.

```
triagetool serve --port 8000
```

The index lists the advisories in triage, with links to the other states and one column per tool. Each advisory has its own page with the full verdicts, where file references link to the code on GitHub. Colors follow the word: green for a fine answer (`distinct`, `valid`, `holds`), red for one that asks for action (`same_bug`, `invalid`, `fails`, a high severity), yellow for unsure, blue for merely interesting.

## AI Disclosure

This repository was created with assistance from Claude.