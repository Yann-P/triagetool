"""Run every tool on each repository's advisories in triage, keeping the verdicts under data/"""

import argparse
from pathlib import Path

from triagetool import dedup, host, legit, store

TOOLS = {"dedup": dedup, "legit": legit}


def add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("repos", type=Path, help="a file with one owner/name per line")
    parser.add_argument("--since", default="5 years ago", help="how much git history to clone (default: %(default)s)")
    parser.add_argument("--force", action="store_true", help="run again even when a result is stored")


def read_repos(path: Path) -> list[str]:
    """owner/name per line, or owner and name separated by whitespace. Blank lines and # comments are skipped."""
    repos = []
    for line in path.read_text().splitlines():
        words = line.split("#")[0].replace("/", " ").split()
        if len(words) == 2:
            repos.append("/".join(words))
        elif words:
            raise host.ToolError(f"{path}: cannot read {line!r} as owner/name")
    return repos


def todo(advisories: list[dict], force: bool) -> list[tuple[str, str]]:
    """(ghsa, tool name) pairs still to run: every advisory in triage, minus stored results unless force."""
    pairs = []
    for adv in advisories:
        if adv["state"] != "triage":
            continue
        stored = store.load_verdicts(adv["ghsa"])
        for name in TOOLS:
            if force or "result" not in stored.get(name, {}):
                pairs.append((adv["ghsa"], name))
    return pairs


def main(args: argparse.Namespace) -> None:
    counts = {"repos": 0, "ran": 0, "skipped": 0, "errors": 0}
    saved = store.load_advisories()["advisories"]
    for repo in read_repos(args.repos):
        try:
            advisories = host.fetch_advisories(repo)
        except host.ToolError as err:
            print(f"{repo}: {err}")
            continue
        counts["repos"] += 1
        fresh = [host.summary(adv, repo) for adv in advisories]
        saved = store.replace_repo(saved, repo, fresh)
        store.save_advisories(saved)
        pairs = todo(fresh, args.force)
        counts["skipped"] += sum(adv["state"] == "triage" for adv in fresh) * len(TOOLS) - len(pairs)
        if not pairs:
            continue
        with host.workdir() as work:
            host.write_ghsas(advisories, work)
            host.clone(repo, args.since, work)
            for ghsa, name in pairs:
                print(f"{ghsa} {name}: running on {repo}", flush=True)
                verdict = {"tool": name, "ran_at": store.now()}
                try:
                    verdict["result"] = host.judge(TOOLS[name], ghsa, work)
                    print(f"{ghsa} {name}: ok")
                except host.ToolError as err:
                    verdict["error"] = str(err)
                    counts["errors"] += 1
                    print(f"{ghsa} {name}: error, see {store.verdict_path(ghsa, name)}")
                store.save_verdict(ghsa, verdict)
                counts["ran"] += 1
    print(f"{counts['repos']} repos, ran {counts['ran']}, skipped {counts['skipped']}, errors {counts['errors']}")
