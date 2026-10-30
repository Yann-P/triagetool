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

## Working with many repositories

If you are dealing with multiple GitHub organizations or repositories, [github-security-overview](https://github.com/Yann-P/github-security-overview) can help (but is not directly integrated in this tool, you have to use it separately).

## AI Disclosure

This repository was created with assistance from Claude.