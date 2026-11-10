"""From a list of repositories to a stored verdict for every report in triage."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from triagetool import claim, host, store, threatmodel, verdict, writeup

# repositories fetched or cloned at once
FETCHES = 8


def read_repos(arguments: list[str]) -> list[str]:
    """Each argument is owner/name, or a file of them, one per line. Blank lines and # comments are skipped."""
    repos = []
    for argument in arguments:
        if Path(argument).is_file():
            lines = Path(argument).read_text().splitlines()
        else:
            lines = [argument]
        for line in lines:
            name = line.split("#")[0]
            if name.strip():
                repos.append(host.repo_name(name))
    return repos


def fetch(repo: str) -> list[dict] | None:
    """Fetch one repository's advisories and store their summaries. None when the fetch failed."""
    try:
        advisories = host.fetch_advisories(repo)
    except host.ToolError as error:
        print(f"{repo}: {error}", flush=True)
        return None
    summaries = [host.summary(advisory) for advisory in advisories]
    store.save(repo, "advisories", {"advisories": summaries})
    return advisories


def sync(repos: list[str]) -> dict:
    """Fetch every repository, several at once. Returns repo -> advisories as GitHub has them."""
    with ThreadPoolExecutor(FETCHES) as pool:
        results = list(pool.map(fetch, repos))
    fetched = {}
    for repo, advisories in zip(repos, results):
        if advisories is not None:
            fetched[repo] = advisories
    return fetched


def attempt(label: str, key: str, function, *arguments) -> dict:
    """{key: what the function returns}, or the error it stopped on. Either one is a record to store."""
    try:
        record = {key: function(*arguments)}
        print(f"{label}: ok", flush=True)
    except host.ToolError as error:
        record = {"error": str(error)}
        print(f"{label}: error", flush=True)
    return record


def todo(repo: str, advisories: list[dict], force: bool, retry_errors: bool, rewrite: bool = False) -> dict:
    """ghsa -> stored record, for the reports in triage that still need a verdict or its write-ups.

    With force, every report in triage, from scratch. With rewrite, every one that has a verdict gets new write-ups.
    Without retry_errors, what failed last time is left alone: the report itself, or every report of a repository
    whose threat model audit failed.
    """
    if not retry_errors and "error" in store.load(repo, "threatmodel"):
        return {}
    records = {}
    for advisory in advisories:
        if force:
            record = {}
        else:
            record = store.load(repo, advisory["ghsa_id"])
        if rewrite:
            record.pop("texts", None)
        failed = "error" in record and not retry_errors
        unfinished = "verdict" not in record or "texts" not in record
        if advisory["state"] == "triage" and unfinished and not failed:
            records[advisory["ghsa_id"]] = record
    return records


def triage(repo: str, advisories: list[dict], records: dict, since: str, reaudit: bool, agents) -> None:
    """Clone once, audit the threat model once, then restate, check and write up every report in records.

    agents is the pool every model run goes through. With reaudit, the stored threat model audit is redone.
    A record that already holds a verdict is only written up.
    """
    with host.workdir() as work:
        code = work / "code"
        try:
            host.clone(repo, since, code)
        except host.ToolError as error:
            print(f"{repo}: {error}", flush=True)
            return

        model = store.load(repo, "threatmodel")
        if reaudit or "audit" not in model:
            # submitted to agents like every other model run, so that --jobs caps them all
            audit = agents.submit(attempt, f"{repo} threat model", "audit", threatmodel.audit, code, work)
            model = audit.result()
            store.save(repo, "threatmodel", model)
        if "error" in model:
            # its reports stay unanalysed until the audit works
            return

        def restate(advisory):
            """The claim of a report in triage, stored or new. None when the clerk failed."""
            ghsa = advisory["ghsa_id"]
            if ghsa in records:
                # with --force this record is empty, so the claim is restated
                record = records[ghsa]
            else:
                record = store.load(repo, ghsa)
            if "claim" not in record:
                record = attempt(f"{ghsa} claim", "claim", claim.distill, advisory, work)
                store.save(repo, ghsa, record)
            return record.get("claim")

        # the check of one report reads the claims of the others, so every claim comes first
        in_triage = [advisory for advisory in advisories if advisory["state"] == "triage"]
        restated = list(agents.map(restate, in_triage))
        claims = {}
        for advisory, restated_claim in zip(in_triage, restated):
            if restated_claim:
                claims[advisory["ghsa_id"]] = restated_claim

        def check(ghsa):
            earlier = records[ghsa]
            outcome = attempt(
                f"{ghsa} verdict",
                "verdict",
                verdict.investigate,
                ghsa,
                advisories,
                claims,
                model["audit"],
                earlier,
                code,
                work,
            )
            record = {"claim": claims[ghsa], **outcome}
            if "hint" in earlier:
                record["hint"] = earlier["hint"]
            if "error" in outcome and "previous" in earlier:
                # the second look failed, so the answer it was meant to replace is kept for the next try
                record["previous"] = earlier["previous"]
            store.save(repo, ghsa, record)

        to_check = [ghsa for ghsa in records if ghsa in claims and "verdict" not in records[ghsa]]
        # list() waits for every check, and raises again what one of them raised
        list(agents.map(check, to_check))

        def write(pair):
            ghsa, level = pair
            return attempt(f"{ghsa} {level} text", "text", writeup.write, level, store.load(repo, ghsa), work)

        to_write = []
        for ghsa, earlier in records.items():
            if "texts" not in earlier and "verdict" in store.load(repo, ghsa):
                to_write.append(ghsa)
        pairs = [(ghsa, level) for ghsa in to_write for level in writeup.LENGTHS]
        written = list(agents.map(write, pairs))
        for ghsa in to_write:
            texts = {}
            for (written_ghsa, level), outcome in zip(pairs, written):
                if written_ghsa == ghsa and "text" in outcome:
                    texts[level] = outcome["text"]
            # a level that failed is left out, and the page falls back to the investigator's own words for it
            record = store.load(repo, ghsa)
            record["texts"] = texts
            store.save(repo, ghsa, record)


def run(repos: list[str], since: str, force: bool, jobs: int, retry_errors: bool = True, rewrite: bool = False) -> None:
    """Fetch every repository, then analyse its reports in triage that are not finished yet."""
    fetched = sync(repos)
    pending = {}
    report_count = 0
    for repo, advisories in fetched.items():
        records = todo(repo, advisories, force, retry_errors, rewrite)
        if records:
            pending[repo] = records
            report_count += len(records)
    print(f"{len(fetched)} repositories, {report_count} reports to analyse", flush=True)
    if not pending:
        return
    # pool works on several repositories at once; they all share agents, so --jobs caps the agents running in total
    with host.sandbox(), ThreadPoolExecutor(jobs) as agents, ThreadPoolExecutor(FETCHES) as pool:
        running = []
        for repo, records in pending.items():
            running.append(pool.submit(triage, repo, fetched[repo], records, since, force, agents))
        for job in running:
            job.result()


def look_again(repo: str, ghsas: list[str], reaudit: bool, since: str, jobs: int) -> None:
    """Check some reports of one repository again, for the inbox. An error lands on their cards, not in a terminal."""
    try:
        advisories = host.fetch_advisories(repo)
        records = {ghsa: store.load(repo, ghsa) for ghsa in ghsas}
        with host.sandbox(), ThreadPoolExecutor(jobs) as agents:
            triage(repo, advisories, records, since, reaudit, agents)
    except host.ToolError as error:
        for ghsa in ghsas:
            record = store.load(repo, ghsa)
            if "verdict" not in record:
                store.save(repo, ghsa, {**record, "error": str(error)})
