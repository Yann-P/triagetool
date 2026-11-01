"""Entrypoint"""

import argparse
import sys
from functools import partial

from triagetool import batch, host, web
from triagetool.batch import TOOLS


def serve(args: argparse.Namespace) -> None:
    print(f"http://localhost:{args.port}/", flush=True)
    web.serve(args.port)


def main() -> None:
    parser = argparse.ArgumentParser(prog="triagetool")
    subparsers = parser.add_subparsers(required=True)
    for name, tool in TOOLS.items():
        sub = subparsers.add_parser(name, help=tool.__doc__.splitlines()[0])
        host.add_args(sub)
        sub.set_defaults(main=partial(host.triage, tool=tool))
    sub = subparsers.add_parser("batch", help=batch.__doc__.splitlines()[0])
    batch.add_args(sub)
    sub.set_defaults(main=batch.main)
    sub = subparsers.add_parser("serve", help="browse advisories and verdicts in a web page")
    sub.add_argument("--port", type=int, default=8000, help="default: %(default)s")
    sub.set_defaults(main=serve)
    args = parser.parse_args()
    try:
        args.main(args)
    except host.ToolError as err:
        sys.exit(str(err))


if __name__ == "__main__":
    main()
