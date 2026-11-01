# SPDX-License-Identifier: Apache-2.0
"""``python -m idemcore trace verify|show|replay FILE``."""
import sys

from .trace import _cli


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] != "trace":
        print("usage: python -m idemcore trace {verify,show,replay} FILE", file=sys.stderr)
        return 2
    return _cli(args[1:])


if __name__ == "__main__":
    raise SystemExit(main())
