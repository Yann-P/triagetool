"""The trusted side: fetch with the GitHub token, run the sandbox, help check what comes back."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

SANDBOX = Path(__file__).resolve().parent / "sandbox"
GHSA_RE = re.compile(r"GHSA(-[2-9cfghjmpqrvwx]{4}){3}")
REF_RE = re.compile(r"(code/[^\s:]+)(:\d+(-\d+)?)?")
MAX_LINE = 400  # caps on text the agent wrote, it is untrusted
MAX_TEXT = 800
KEEP = [
    "ghsa_id",
    "cve_id",
    "state",
    "created_at",
    "published_at",
    "withdrawn_at",
    "summary",
    "description",
    "cwe_ids",
    "vulnerabilities",
]


def run(cmd, **kwargs):
    """Quiet on success; dumps the combined output on failure."""
    proc = subprocess.run(
        cmd,
        check=False,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )
    if proc.returncode:
        sys.exit(f"{proc.stdout}{cmd[0]} exited {proc.returncode}")
    return proc


def step(msg: str) -> None:
    print(f"{msg}...", file=sys.stderr, flush=True)  # stderr keeps stdout as pure JSON


def ghsa_id(value: str) -> str:
    if not GHSA_RE.fullmatch(value):
        raise ValueError(f"bad GHSA id: {value!r}")
    return value


def add_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("repo", help="owner/name")
    parser.add_argument("ghsa", type=ghsa_id, help="GHSA-xxxx-xxxx-xxxx")
    parser.add_argument("--since", default="5 years ago", help="how much git history to clone (default: %(default)s)")


@contextmanager
def workdir():
    # under $HOME: Colima and Docker Desktop don't share the system temp dir with containers
    with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".triagetool-") as tmp:
        yield Path(tmp)


def fetch(repo: str, since: str, work: Path) -> None:
    """Talks to GitHub: advisories through gh, code through git."""
    (work / "ghsas").mkdir()
    step(f"Fetching advisories for {repo}")
    out = run(["gh", "api", f"repos/{repo}/security-advisories", "--paginate", "--slurp"]).stdout
    index = []
    for page in json.loads(out):
        for adv in page:
            gid = ghsa_id(adv["ghsa_id"])
            (work / "ghsas" / f"{gid}.json").write_text(json.dumps({key: adv[key] for key in KEEP}, indent=2))
            index.append(
                f"{gid}  {adv['state']:9}  {adv['created_at'][:10]}  {adv['cve_id'] or '-':14}  {adv['summary']}"
            )
    (work / "ghsas" / "index.txt").write_text("\n".join(sorted(index)) + "\n")
    step(f"Cloning {repo}")
    run(
        [
            "git",
            "clone",
            "--quiet",
            "--single-branch",
            f"--shallow-since={since}",
            f"https://github.com/{repo}",
            str(work / "code"),
        ]
    )


def run_sandbox(prompt: str, schema: dict, work: Path) -> dict:
    """Returns the agent's structured output. Untrusted."""
    (work / "task").mkdir()
    (work / "task" / "prompt.txt").write_text(prompt)
    (work / "task" / "schema.json").write_text(json.dumps(schema))
    os.chmod(work, 0o755)  # the container reads it as uid 1000
    compose = ["docker", "compose", "--progress", "quiet", "-f", str(SANDBOX / "compose.yml")]
    env = {**os.environ, "WORK": str(work)}
    try:
        step("Building sandbox")
        run([*compose, "build"], env=env)
        step("Running the agent")
        proc = subprocess.run(
            [*compose, "run", "--rm", "-T", "agent"],
            check=False,
            env=env,
            text=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
    finally:
        subprocess.run([*compose, "down"], check=False, env=env, capture_output=True)
    result = json.loads(proc.stdout) if proc.stdout.startswith("{") else {}
    if "structured_output" not in result:
        sys.exit(f"agent failed: {result.get('result') or proc.stdout + proc.stderr}")
    return result["structured_output"]


def has_file(work: Path, ref: str) -> bool:
    """ref looks like code/path/to/file.py:42"""
    match = REF_RE.fullmatch(str(ref))
    return bool(match) and (work / match[1]).is_file()


def triage(args: argparse.Namespace, prompt: str, schema: dict, validate) -> None:
    """Fetch, run the agent on one advisory, print the validated verdict."""
    with workdir() as work:
        fetch(args.repo, args.since, work)
        if not (work / "ghsas" / f"{args.ghsa}.json").exists():
            sys.exit(f"{args.ghsa} is not an advisory of {args.repo}")
        raw = run_sandbox(prompt.replace("{target}", args.ghsa), schema, work)
        try:
            verdict = validate(raw, args.ghsa, work)
        except ValueError as err:
            sys.exit(f"{json.dumps(raw, indent=2)}\nrejected: {err}")
    print(json.dumps(verdict, indent=2))  # for a human to read, never to auto-close on
