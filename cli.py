#!/usr/bin/env python3
"""CLI for the DeFi vulnerability finding benchmark.

Usage:
    uv run python cli.py pentest --list
    uv run python cli.py pentest --case aizpttoken
    uv run python cli.py pentest --limit 10
    uv run python cli.py pentest --all --concurrency 2
"""

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def pentest_command(args: argparse.Namespace) -> None:
    """Handle the pentest subcommand."""
    from src.agents import AGENTS, get_agent
    from src.config import BenchmarkConfig
    from src.pipeline import BenchmarkPipeline

    # ── Build config ──────────────────────────────────────────────────────────
    config = BenchmarkConfig(
        time_limit_minutes=args.time_limit,
        skip_foundry=args.no_foundry,
        run_evaluation=not args.no_eval,
        max_iterations=args.max_iterations,
    )

    # ── Resolve agent ─────────────────────────────────────────────────────────
    agent_cls = get_agent(args.agent)

    # ── Load pipeline ─────────────────────────────────────────────────────────
    pipeline = BenchmarkPipeline(agent_cls=agent_cls, config=config)

    # ── --list ────────────────────────────────────────────────────────────────
    if args.list:
        after_ts = _parse_after(args.after)
        cases = pipeline.list_cases(
            after_timestamp=after_ts,
            version=args.version,
            sort=args.sort,
        )

        chain_names = {
            1: "ETH", 56: "BSC", 8453: "Base", 137: "Poly",
            42161: "Arb", 10: "Opt", 43114: "Avax",
        }
        total_usd = sum(c.get("lost_amount_usd") or 0 for c in cases)
        total_ref = sum(len(c.get("reference_findings", [])) for c in cases)

        print(
            f"\nAvailable Cases: {len(cases)}  |  "
            f"Total ref loss: ${total_usd:,.0f}  |  "
            f"Total reference findings: {total_ref}"
        )
        print(
            f"\n  {'ID':<28} {'Date':>10}  "
            f"{'Chain':>5}  {'Loss (USD)':>12}  {'Ref':>3}  {'Ver':>3}"
        )
        print("-" * 76)
        for c in cases:
            date_str = (
                datetime.fromtimestamp(c["exploit_timestamp"], tz=UTC).strftime("%Y-%m-%d")
                if c.get("exploit_timestamp")
                else "unknown"
            )
            chain_str = chain_names.get(c.get("chain_id", 0), str(c.get("chain_id", "?")))
            loss_str = (
                f"${c['lost_amount_usd']:>11,.0f}"
                if c.get("lost_amount_usd")
                else "     unknown"
            )
            n_ref = len(c.get("reference_findings", []))
            ver = c.get("dataset_version", "?")
            print(
                f"  {c['id']:<28} {date_str:>10}  "
                f"{chain_str:>5}  {loss_str}  {n_ref:>3}  {ver:>3}"
            )

        print(f"\nAgents available: {', '.join(sorted(AGENTS))}")
        return

    # ── Determine output directory ────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (
        Path(args.output)
        if args.output
        else Path(f"results/pentest_{args.agent}_{timestamp}")
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    results_jsonl = output_dir / "results.jsonl"
    summary_json = output_dir / "summary.json"

    after_ts = _parse_after(args.after)

    async def _run() -> None:
        # ── Single case ───────────────────────────────────────────────────────
        if args.case:
            if args.case not in pipeline.cases:
                available = sorted(pipeline.cases)[:10]
                print(f"Unknown case: {args.case}")
                print(f"Available (first 10): {', '.join(available)}...")
                sys.exit(1)

            case = pipeline.cases[args.case]
            print(f"\nRunning case: {case['id']}")
            print(f"  Target:  {case['target_contract']}")
            print(f"  Chain:   {case.get('chain_id')}, Block: {case.get('block_number')}")
            print(f"  Agent:   {args.agent}")
            print(f"  Output:  {output_dir}")
            print()

            result = await pipeline.run_case(case, output_path=results_jsonl)

            print(f"\nResult: {case['id']}")
            print(f"  Findings: {len(result.findings)}")
            for f in result.findings:
                print(f"    [{f.severity.upper()}] {f.title}")
            if result.evaluation:
                recall_pct = f"{result.evaluation.recall * 100:.0f}%"
                print(
                    f"  Recall: {recall_pct} "
                    f"({result.evaluation.matched_count}/{result.evaluation.reference_count} "
                    f"reference findings matched)"
                )
                print(f"  Novel: {result.evaluation.novel_findings_count} findings")
            if result.error:
                print(f"  Error: {result.error}")
            print(f"  Time: {result.execution_time_seconds:.1f}s")

            pipeline.save_summary([result], summary_json)
            print(f"\nResults saved to: {output_dir}")

        # ── Batch run ─────────────────────────────────────────────────────────
        else:
            case_ids = None
            if args.cases:
                case_ids = [c.strip() for c in args.cases.split(",")]

            n_cases = len(
                pipeline.list_cases(after_timestamp=after_ts, version=args.version)
                if not case_ids
                else [pipeline.cases[cid] for cid in case_ids if cid in pipeline.cases]
            )
            limit = args.limit or n_cases

            print(
                f"\nRunning {min(limit, n_cases)} cases  |  "
                f"agent={args.agent}  concurrency={args.concurrency}"
            )
            print(f"Output: {output_dir}\n")

            results = await pipeline.run_batch(
                case_ids=case_ids,
                limit=args.limit,
                concurrency=args.concurrency,
                after_timestamp=after_ts,
                version=args.version,
                output_path=results_jsonl,
            )

            evaluated = [r for r in results if r.evaluation]
            avg_recall = (
                sum(r.evaluation.recall for r in evaluated) / len(evaluated)
                if evaluated
                else 0.0
            )
            errors = sum(1 for r in results if r.error)

            print(
                f"\nSummary: {len(results)} cases  |  "
                f"avg recall={avg_recall * 100:.1f}%  |  "
                f"errors={errors}"
            )

            pipeline.save_summary(results, summary_json)
            print(f"Results saved to: {output_dir}")

    asyncio.run(_run())


def _parse_after(after: str | None) -> int | None:
    if not after:
        return None
    return int(datetime.strptime(after, "%Y-%m-%d").replace(tzinfo=UTC).timestamp())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeFi Vulnerability Finding Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  uv run python cli.py pentest --list
  uv run python cli.py pentest --case aizpttoken
  uv run python cli.py pentest --case aizpttoken --no-eval
  uv run python cli.py pentest --limit 10
  uv run python cli.py pentest --all --concurrency 2 --output results/my_run
  uv run python cli.py pentest --agent baseline --version v1
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # ── pentest command ───────────────────────────────────────────────────────
    pentest_parser = subparsers.add_parser(
        "pentest",
        help="Run vulnerability identification agent on DeFi benchmark cases",
    )

    # Case selection
    pentest_parser.add_argument("--list", action="store_true", help="List available cases")
    pentest_parser.add_argument("--case", type=str, help="Single case ID to run")
    pentest_parser.add_argument(
        "--cases", type=str, help="Comma-separated case IDs to run"
    )
    pentest_parser.add_argument("--all", action="store_true", help="Run all cases")
    pentest_parser.add_argument("--limit", type=int, help="Maximum cases to run")
    pentest_parser.add_argument(
        "--after", type=str, metavar="YYYY-MM-DD",
        help="Only include cases after this date",
    )
    pentest_parser.add_argument(
        "--version", type=str, help="Filter by dataset version (e.g. v1)"
    )
    pentest_parser.add_argument(
        "--sort",
        type=str,
        choices=["date", "amount", "id"],
        default="date",
        help="Sort order for --list (default: date)",
    )

    # Agent
    pentest_parser.add_argument(
        "--agent",
        type=str,
        default="baseline",
        help="Agent to use (default: baseline). See src/agents/__init__.py for options.",
    )

    # Execution
    pentest_parser.add_argument(
        "--concurrency", type=int, default=1, help="Parallel runs (default: 1)"
    )
    pentest_parser.add_argument(
        "--time-limit",
        type=float,
        default=60.0,
        dest="time_limit",
        help="Per-case time limit in minutes (default: 60)",
    )
    pentest_parser.add_argument(
        "--max-iterations",
        type=int,
        default=500,
        dest="max_iterations",
        help="Agent iteration limit / langgraph recursion_limit (default: 500)",
    )
    pentest_parser.add_argument(
        "--no-foundry",
        action="store_true",
        dest="no_foundry",
        help="Skip Foundry project setup (faster, no forge commands available to agent)",
    )
    pentest_parser.add_argument(
        "--no-eval",
        action="store_true",
        dest="no_eval",
        help="Skip LLM-as-judge evaluation step",
    )

    # Output
    pentest_parser.add_argument(
        "--output", type=str, help="Output directory (default: results/pentest_{agent}_{ts}/)"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "pentest":
        # Require an explicit action — prevents silently running all cases
        if not (
            args.list
            or args.case
            or args.cases
            or getattr(args, "all", False)
            or args.limit
        ):
            pentest_parser.print_help()
            print(
                "\nerror: specify --list, --case, --cases, --all, or --limit"
            )
            sys.exit(1)
        pentest_command(args)


if __name__ == "__main__":
    main()
