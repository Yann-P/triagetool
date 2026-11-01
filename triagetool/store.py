"""Everything under data/ in the current directory: the advisory list and one file per verdict."""

import json
from datetime import UTC, datetime
from pathlib import Path

DATA_DIR = Path("data")


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def advisories_path() -> Path:
    return DATA_DIR / "advisories.json"


def save_advisories(advisories: list[dict]) -> None:
    write_json(advisories_path(), {"fetched_at": now(), "advisories": advisories})


def load_advisories() -> dict:
    """The saved advisories, or none with an empty fetched_at before the first batch."""
    path = advisories_path()
    if not path.exists():
        return {"fetched_at": "", "advisories": []}
    return json.loads(path.read_text())


def replace_repo(advisories: list[dict], repo: str, fresh: list[dict]) -> list[dict]:
    """The list with every advisory of repo (owner/name) swapped for the fresh ones."""
    kept = [adv for adv in advisories if f"{adv['org']}/{adv['repo']}" != repo]
    return kept + fresh


def verdict_path(ghsa: str, tool_name: str) -> Path:
    return DATA_DIR / "verdicts" / f"{ghsa}.{tool_name}.json"


def save_verdict(ghsa: str, verdict: dict) -> None:
    write_json(verdict_path(ghsa, verdict["tool"]), verdict)


def load_verdicts(ghsa: str) -> dict:
    """tool name -> Verdict, for the tools that have a file."""
    verdicts = {}
    for path in (DATA_DIR / "verdicts").glob(f"{ghsa}.*.json"):
        verdict = json.loads(path.read_text())
        verdicts[verdict["tool"]] = verdict
    return verdicts
