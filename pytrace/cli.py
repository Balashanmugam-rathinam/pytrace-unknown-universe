import argparse

from . import APP_NAME, __version__
from .traceroute import trace


def create_parser():
    parser = argparse.ArgumentParser(
        prog="pytrace",
        description=APP_NAME
    )

    parser.add_argument(
        "target",
        help="Target hostname or IPv4 address"
    )

    parser.add_argument(
        "-m",
        "--max-hops",
        type=int,
        default=30,
        help="Maximum number of hops (default: 30)"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout per probe in seconds (default: 2)"
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"PyTrace {__version__}"
    )

    return parser


def main():

    parser = create_parser()
    args = parser.parse_args()

    if args.max_hops < 1:
        parser.error(
            "max-hops must be greater than 0"
        )

    if args.timeout <= 0:
        parser.error(
            "timeout must be greater than 0"
        )

    try:

        trace(
            target=args.target,
            max_hops=args.max_hops,
            timeout=args.timeout
        )

    except ValueError as exc:

        parser.error(str(exc))


if __name__ == "__main__":
    main()