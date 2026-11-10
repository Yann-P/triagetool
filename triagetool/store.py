"""Everything under data/ in the current directory, one folder per repository.

data/repos/<owner>/<name>/advisories.json   every advisory of the repository, in every state
data/repos/<owner>/<name>/threatmodel.json  what its docs say about its security boundary
data/repos/<owner>/<name>/<GHSA>.json       the claim and the verdict for one report
"""

import json
from datetime import UTC, datetime
from pathlib import Path

DATA_DIR = Path("data")


def path(repo: str, name: str) -> Path:
    return DATA_DIR / "repos" / repo / f"{name}.json"


def load(repo: str, name: str) -> dict:
    """The stored record, or {} when there is none."""
    file = path(repo, name)
    if not file.exists():
        return {}
    return json.loads(file.read_text())


def save(repo: str, name: str, record: dict) -> None:
    file = path(repo, name)
    file.parent.mkdir(parents=True, exist_ok=True)
    stamped = {"saved_at": datetime.now(UTC).isoformat(timespec="seconds"), **record}
    # written aside then moved into place, so a reader never sees half a file
    unfinished = file.with_suffix(".unfinished")
    unfinished.write_text(json.dumps(stamped, indent=2) + "\n")
    unfinished.replace(file)


def repos() -> list[str]:
    """Every repository that was fetched at least once, as owner/name."""
    names = []
    for file in (DATA_DIR / "repos").glob("*/*/advisories.json"):
        name_folder = file.parent
        owner_folder = name_folder.parent
        names.append(f"{owner_folder.name}/{name_folder.name}")
    return sorted(names)
