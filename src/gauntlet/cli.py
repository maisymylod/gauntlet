"""Command-line entry point.

Phase 1 ships the skeleton: argument parsing and subcommand dispatch. The corpus
runner (``run``) and the attack-surface report (``report``) are filled in by
later phases.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gauntlet",
        description="Adversarial test and defense harness for LLM agents.",
    )
    parser.add_argument("--version", action="version", version=f"gauntlet {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Run the attack corpus against a target.")
    run.add_argument(
        "--defenses",
        choices=["off", "on", "both"],
        default="off",
        help="Run with defenses off, on, or both (for comparison).",
    )
    run.add_argument("--run-id", default=None, help="Identifier for this run.")

    report = sub.add_parser("report", help="Render an attack-surface report from a run.")
    report.add_argument("--run-id", required=True, help="Run to report on.")

    return parser


def cmd_run(args: argparse.Namespace) -> int:
    from .attacks.base import load_corpus
    from .attacks.runner import offline_clients, run_corpus
    from .report.scoring import format_summary, summarize
    from .target.reference_agent import default_context

    if args.defenses != "off":
        print("Phase 2 wires only --defenses off; on/both arrive in Phase 3. Running off.")

    context = default_context()
    cases = load_corpus()
    make_agent, make_judge = offline_clients(context)
    outcomes = run_corpus(
        cases,
        context=context,
        make_agent_client=make_agent,
        make_judge_client=make_judge,
    )
    score = summarize(outcomes)
    print(format_summary("defenses=off (offline replay)", score))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    print(f"gauntlet report (run-id={args.run_id}): reporting lands in Phase 5.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "report":
        return cmd_report(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
