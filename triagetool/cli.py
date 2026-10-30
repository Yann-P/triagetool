"""Entrypoint"""

import argparse

from triagetool import dedup, legit

TOOLS = {"dedup": dedup, "legit": legit}


def main() -> None:
    parser = argparse.ArgumentParser(prog="triagetool")
    subparsers = parser.add_subparsers(required=True)
    for name, tool in TOOLS.items():
        sub = subparsers.add_parser(name, help=tool.__doc__.splitlines()[0])
        tool.add_args(sub)
        sub.set_defaults(main=tool.main)
    args = parser.parse_args()
    args.main(args)
