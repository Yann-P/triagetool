"""The command line: one subcommand each for run, serve, chat and threatmodel."""

import argparse
import json
import sys

from triagetool import chat, host, pipeline, threatmodel, web


def audit(args: argparse.Namespace) -> None:
    """Works on any repository you can read, with no advisory."""
    with host.sandbox(), host.workdir() as work:
        host.clone(host.repo_name(args.repo), args.since, work / "code")
        print(json.dumps(threatmodel.audit(work / "code", work), indent=2))


def run(args: argparse.Namespace) -> None:
    host.stop_on_interrupt()
    pipeline.run(pipeline.read_repos(args.repos), args.since, args.force, args.jobs, rewrite=args.rewrite)


def main() -> None:
    parser = argparse.ArgumentParser(prog="triagetool")
    subparsers = parser.add_subparsers(required=True)
    since = argparse.ArgumentParser(add_help=False)
    since.add_argument("--since", default="5 years ago", help="how much git history to clone (default: %(default)s)")

    run_parser = subparsers.add_parser(
        "run", parents=[since], help="analyse every report in triage that has no verdict yet"
    )
    run_parser.add_argument("repos", nargs="+", help="owner/name, or a file with one per line")
    run_parser.add_argument("--jobs", type=int, default=4, help="agents running at once (default: %(default)s)")
    run_parser.add_argument("--force", action="store_true", help="analyse again what already has a verdict")
    run_parser.add_argument("--rewrite", action="store_true", help="write the three write-ups again, keeping verdicts")
    run_parser.set_defaults(main=run)

    serve_parser = subparsers.add_parser("serve", parents=[since], help="the inbox, as a web page")
    serve_parser.add_argument("--port", type=int, default=8000, help="default: %(default)s")
    serve_parser.add_argument("repos", nargs="*", help="owner/name, or a file. Default: every repository in data/")
    serve_parser.add_argument("--jobs", type=int, default=4, help="agents running at once (default: %(default)s)")
    serve_parser.add_argument(
        "--every",
        type=int,
        default=15,
        metavar="MINUTES",
        help="how often to fetch and analyse new reports, 0 for never (default: %(default)s)",
    )
    serve_parser.set_defaults(main=web.serve)

    chat_parser = subparsers.add_parser("chat", parents=[since], help="talk to the sandboxed model about one report")
    chat_parser.add_argument("ghsa", type=host.ghsa_id, help="GHSA-xxxx-xxxx-xxxx")
    chat_parser.set_defaults(main=chat.main)

    threatmodel_parser = subparsers.add_parser(
        "threatmodel", parents=[since], help="audit the security docs of one repository"
    )
    threatmodel_parser.add_argument("repo", help="owner/name")
    threatmodel_parser.set_defaults(main=audit)

    args = parser.parse_args()
    try:
        args.main(args)
    except KeyboardInterrupt:
        sys.exit("Stopped. Every agent was killed, and what was in progress will run again next time.")
    except host.ToolError as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
