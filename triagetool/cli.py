"""Entrypoint"""

import argparse
import sys
from functools import partial

from triagetool import dedup, host, legit

TOOLS = {"dedup": dedup, "legit": legit}


def main() -> None:
    parser = argparse.ArgumentParser(prog="triagetool")
    subparsers = parser.add_subparsers(required=True)
    for name, tool in TOOLS.items():
        sub = subparsers.add_parser(name, help=tool.__doc__.splitlines()[0])
        host.add_args(sub)
        sub.set_defaults(main=partial(host.triage, tool=tool))
    args = parser.parse_args()
    try:
        args.main(args)
    except host.ToolError as err:
        sys.exit(str(err))


if __name__ == "__main__":
    main()
