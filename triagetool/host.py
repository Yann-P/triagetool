"""The trusted side: talk to GitHub with the user's token, and run agents in the sandbox."""

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

SANDBOX = Path(__file__).resolve().parent / "sandbox"
# one compose project per process, so a chat and a run do not stop each other's proxy
PROJECT = f"triagetool-{os.getpid()}"
COMPOSE = ["docker", "compose", "--progress", "quiet", "-p", PROJECT, "-f", str(SANDBOX / "compose.yml")]
# set once the user interrupts the program: no agent starts after that
STOPPING = threading.Event()
GHSA_RE = re.compile(r"GHSA(-[2-9cfghjmpqrvwx]{4}){3}")
REPO_RE = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
REFERENCE_RE = re.compile(r"code/([^\s:]+)(?::(\d+)(?:-(\d+))?)?")
# caps on text an agent wrote, it is untrusted
MAX_LINE = 300
MAX_TEXT = 700
MAX_FULL = 1800


class Agent(NamedTuple):
    """One job for the sandboxed model: what to do, the shape of its answer, and how much it may spend."""

    prompt: str
    schema: dict
    model: str
    effort: str
    tools: str
    turns: int


class Stopped(Exception):
    """The user interrupted the program while this agent was running. Nothing is stored for it."""


class ToolError(Exception):
    """A failure the user has to read: a command that failed, a bad argument, a rejected answer."""


def run(command, env=None):
    """Quiet on success; raises with the combined output on failure."""
    process = subprocess.run(
        command,
        check=False,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    if process.returncode != 0:
        raise ToolError(f"{process.stdout}{command[0]} exited {process.returncode}")
    return process


def step(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def one_line(text: str) -> str:
    """The text with every run of spaces and line breaks turned into one space."""
    return " ".join(text.split())


def day(timestamp: str) -> str:
    """2026-10-01 from 2026-10-01T10:00:00Z."""
    return timestamp[:10]


def ghsa_id(value: str) -> str:
    if not GHSA_RE.fullmatch(value):
        raise ValueError(f"bad GHSA id: {value!r}")
    return value


def repo_name(value: str) -> str:
    """owner/name, or owner and name separated by whitespace."""
    parts = value.replace("/", " ").split()
    repo = "/".join(parts)
    if not REPO_RE.fullmatch(repo) or parts[-1] in (".", ".."):
        raise ToolError(f"cannot read {value!r} as owner/name")
    return repo


@contextmanager
def workdir():
    # under $HOME: Colima and Docker Desktop don't share the system temp dir with containers
    with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".triagetool-") as directory:
        yield Path(directory)


def fetch_advisories(repo: str) -> list[dict]:
    """Every advisory of the repository, as GitHub returns them."""
    pages = run(["gh", "api", f"repos/{repo}/security-advisories", "--paginate", "--slurp"]).stdout
    advisories = []
    for page in json.loads(pages):
        advisories += page
    return advisories


def summary(advisory: dict) -> dict:
    """The few fields the store keeps and the inbox shows."""
    reporter = ""
    if advisory["author"]:
        reporter = advisory["author"].get("login", "")
    return {
        "ghsa": ghsa_id(advisory["ghsa_id"]),
        "state": advisory["state"],
        "severity": advisory["severity"] or "",
        "title": one_line(advisory["summary"]),
        "created": day(advisory["created_at"]),
        "reporter": reporter,
        "url": advisory["html_url"],
    }


def clone(repo: str, since: str, destination: Path) -> None:
    step(f"{repo}: cloning")
    run(
        [
            "git",
            "clone",
            "--quiet",
            "--single-branch",
            f"--shallow-since={since}",
            f"https://github.com/{repo}",
            str(destination),
        ]
    )


def has_file(code: Path, reference) -> bool:
    """reference looks like code/path/to/file.py:42, code is the clone."""
    match = REFERENCE_RE.fullmatch(str(reference))
    if match is None:
        return False
    path = match.group(1)
    return (code / path).is_file()


def mounts(work: Path = SANDBOX, code: Path = SANDBOX) -> dict:
    """The environment compose.yml reads its two read-only mounts from."""
    return {**os.environ, "WORK": str(work), "CODE": str(code)}


@contextmanager
def sandbox():
    """The image built and the proxy up, for as long as agents run."""
    if not (os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY")):
        raise ToolError("set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY")
    step("Starting the sandbox")
    try:
        run(COMPOSE + ["build"], env=mounts())
        run(COMPOSE + ["up", "--detach", "proxy"], env=mounts())
        yield
    finally:
        remove_containers()


def remove_containers() -> None:
    """Kill and remove everything this process started in Docker: the agents, the proxy and their network."""
    # agents first and by label, because "down" leaves the containers of "compose run" running
    listing = ["docker", "ps", "--all", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"]
    containers = subprocess.run(listing, check=False, text=True, capture_output=True).stdout.split()
    if containers:
        subprocess.run(["docker", "rm", "--force", *containers], check=False, capture_output=True)
    subprocess.run(COMPOSE + ["down", "--timeout", "0"], check=False, env=mounts(), capture_output=True)


def stop_on_interrupt() -> None:
    """Make Ctrl-C and kill stop the agents at once, so that none keeps running, and spending, after the program."""

    def stop(signal_number, frame):
        STOPPING.set()
        remove_containers()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)


def write_files(files: dict, base: Path) -> Path:
    """A new directory under base holding files (relative path -> text), readable from the container."""
    work = Path(tempfile.mkdtemp(dir=base))
    work.chmod(0o755)  # the container reads it as uid 1000
    (work / "code").mkdir()  # where the clone gets mounted
    for name, text in files.items():
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return work


def ask(agent: Agent, files: dict, base: Path, code: Path | None = None) -> dict:
    """Run one agent in the sandbox over files and, when given, the clone. Its answer is untrusted."""
    task = {"task/prompt.txt": agent.prompt, "task/schema.json": json.dumps(agent.schema)}
    work = write_files({**files, **task}, base)
    if code is None:
        code = work / "code"
    settings = [
        f"-eMODEL={agent.model}",
        f"-eEFFORT={agent.effort}",
        f"-eTOOLS={agent.tools}",
        f"-eTURNS={agent.turns}",
    ]
    if STOPPING.is_set():
        raise Stopped
    process = subprocess.run(
        COMPOSE + ["run", "--rm", "-T"] + settings + ["agent"],
        check=False,
        env=mounts(work, code),
        text=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        # its own session, so that Ctrl-C reaches this program first and not the docker client
        start_new_session=True,
    )
    if STOPPING.is_set():
        # the container was killed under it, so whatever it printed is not an answer and not an error to store
        raise Stopped
    try:
        result = json.loads(process.stdout)
    except ValueError:
        result = {}
    if "structured_output" not in result:
        output = process.stdout + process.stderr
        reason = result.get("result") or output[-2000:]
        raise ToolError(f"agent failed: {reason}")
    return result["structured_output"]
