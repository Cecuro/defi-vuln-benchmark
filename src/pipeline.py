"""Benchmark pipeline orchestrator.

Loads cases → fetches Etherscan source → sets up Foundry project →
runs agent → evaluates findings → writes incremental JSONL output.
"""

import asyncio
import json
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .agents.base import AgentFinding, BaseAgent
from .config import BenchmarkConfig, get_rpc_url
from .etherscan import fetch_contract_source
from .evaluation import CaseEvalResult, evaluate_case
from .foundry import setup_foundry_project


@dataclass
class CaseRunResult:
    """Result for a single benchmark case run."""

    case_id: str
    chain_id: int
    agent_name: str
    execution_time_seconds: float
    findings: list[AgentFinding]
    evaluation: CaseEvalResult | None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "chain_id": self.chain_id,
            "agent": self.agent_name,
            "execution_time_seconds": round(self.execution_time_seconds, 1),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "location": f.location,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            "evaluation": self.evaluation.to_dict() if self.evaluation else None,
            "error": self.error,
        }


class BenchmarkPipeline:
    """Runs the vulnerability identification benchmark end-to-end."""

    def __init__(
        self,
        agent_cls: type[BaseAgent],
        config: BenchmarkConfig | None = None,
    ) -> None:
        if config is None:
            config = BenchmarkConfig()
        self.config = config
        self.agent_cls = agent_cls
        self.cases = self._load_cases()

    def _load_cases(self) -> dict[str, dict]:
        """Load cases from JSONL, filtering to status='ready'."""
        dataset_path = Path(self.config.dataset_path)
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")

        cases: dict[str, dict] = {}
        with open(dataset_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if data.get("status") == "ready":
                    cases[data["id"]] = data

        return cases

    def list_cases(
        self,
        after_timestamp: int | None = None,
        version: str | None = None,
        sort: str = "date",
    ) -> list[dict]:
        """List available cases with optional filtering and sorting."""
        cases = list(self.cases.values())

        if after_timestamp:
            cases = [
                c
                for c in cases
                if c.get("exploit_timestamp", 0) > after_timestamp
            ]
        if version:
            cases = [c for c in cases if c.get("dataset_version") == version]

        if sort == "amount":
            return sorted(cases, key=lambda c: c.get("lost_amount_usd") or 0, reverse=True)
        if sort == "date":
            return sorted(cases, key=lambda c: c.get("exploit_timestamp") or 0, reverse=True)
        # Default: sort by id
        return sorted(cases, key=lambda c: c["id"])

    def _append_result(self, result: CaseRunResult, path: Path) -> None:
        """Append a single result to a JSONL file (crash-safe incremental saving)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(result.to_dict()) + "\n")

    async def run_case(
        self,
        case: dict,
        output_path: Path | None = None,
    ) -> CaseRunResult:
        """Run a single benchmark case end-to-end."""
        case_id = case["id"]
        start_time = time.time()

        work_dir = (
            Path(self.config.working_dir) / f"{case_id}_{uuid4().hex[:8]}"
        )
        work_dir.mkdir(parents=True, exist_ok=True)

        findings: list[AgentFinding] = []
        evaluation: CaseEvalResult | None = None
        error: str | None = None

        try:
            # ── 1. Fetch contract source ──────────────────────────────────────
            api_key = os.getenv("ETHERSCAN_API_KEY", "")
            source = await fetch_contract_source(
                address=case["target_contract"],
                chain_id=case["chain_id"],
                api_key=api_key,
                cache_dir=Path(self.config.cache_dir),
            )

            # ── 2. Setup Foundry project ──────────────────────────────────────
            if not self.config.skip_foundry:
                rpc_url = get_rpc_url(case["chain_id"])
                setup_foundry_project(
                    source=source,
                    working_dir=work_dir,
                    block_number=case.get("block_number"),
                    rpc_url=rpc_url,
                    target_address=case["target_contract"],
                    chain_id=case["chain_id"],
                    evm_version=case.get("evm_version"),
                )
            else:
                # Minimal setup: just copy source files to contracts/
                contracts_dir = work_dir / "contracts"
                contracts_dir.mkdir(exist_ok=True)
                for path, content in source.source_files.items():
                    fp = contracts_dir / path.lstrip("/")
                    fp.parent.mkdir(parents=True, exist_ok=True)
                    fp.write_text(content)

                # Write CHALLENGE.md
                (work_dir / "CHALLENGE.md").write_text(
                    f"# Challenge\n\nTarget: `{case['target_contract']}`\n"
                    f"Chain ID: {case['chain_id']}\n"
                    f"Block: {case.get('block_number', 'unknown')}\n"
                )

            # ── 3. Run agent ──────────────────────────────────────────────────
            agent = self.agent_cls()
            findings = await agent.run(
                working_dir=work_dir,
                challenge=case,
                config=self.config,
            )

            # ── 4. Evaluate findings ──────────────────────────────────────────
            if self.config.run_evaluation:
                reference_findings = case.get("reference_findings", [])
                evaluation = await evaluate_case(
                    case_id=case_id,
                    agent_findings=findings,
                    reference_findings=reference_findings,
                    config=self.config,
                )

        except Exception as e:
            error = str(e) or type(e).__name__

        execution_time = time.time() - start_time

        result = CaseRunResult(
            case_id=case_id,
            chain_id=case.get("chain_id", 0),
            agent_name=self.agent_cls.name,
            execution_time_seconds=execution_time,
            findings=findings,
            evaluation=evaluation,
            error=error,
        )

        if output_path:
            self._append_result(result, output_path)

        return result

    async def run_batch(
        self,
        case_ids: list[str] | None = None,
        limit: int | None = None,
        concurrency: int = 1,
        after_timestamp: int | None = None,
        version: str | None = None,
        output_path: Path | None = None,
    ) -> list[CaseRunResult]:
        """Run agent on multiple cases with crash-safe incremental JSONL output."""
        if case_ids:
            cases = [self.cases[cid] for cid in case_ids if cid in self.cases]
        else:
            cases = self.list_cases(
                after_timestamp=after_timestamp,
                version=version,
            )

        if limit:
            cases = cases[:limit]

        if concurrency == 1:
            results = []
            for case in cases:
                result = await self.run_case(case, output_path=output_path)
                results.append(result)
                _log_result(result)
            return results

        sem = asyncio.Semaphore(concurrency)

        async def _run(case: dict) -> CaseRunResult:
            async with sem:
                result = await self.run_case(case, output_path=output_path)
                _log_result(result)
                return result

        gathered = await asyncio.gather(
            *(_run(c) for c in cases), return_exceptions=True
        )

        results = []
        for i, r in enumerate(gathered):
            if isinstance(r, BaseException):
                case = cases[i]
                results.append(
                    CaseRunResult(
                        case_id=case["id"],
                        chain_id=case.get("chain_id", 0),
                        agent_name=self.agent_cls.name,
                        execution_time_seconds=0.0,
                        findings=[],
                        evaluation=None,
                        error=str(r),
                    )
                )
            else:
                results.append(r)

        return results

    def save_summary(self, results: list[CaseRunResult], output_path: Path) -> None:
        """Write aggregate summary JSON."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        total = len(results)
        errors = sum(1 for r in results if r.error)
        evaluated = [r for r in results if r.evaluation]

        avg_recall = (
            sum(r.evaluation.recall for r in evaluated) / len(evaluated)
            if evaluated
            else 0.0
        )
        total_novel = sum(r.evaluation.novel_findings_count for r in evaluated)

        summary = {
            "timestamp": datetime.now(UTC).isoformat(),
            "agent": self.agent_cls.name,
            "total_cases": total,
            "errors": errors,
            "evaluated_cases": len(evaluated),
            "avg_recall": round(avg_recall, 4),
            "total_novel_findings": total_novel,
        }

        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2)


def _log_result(result: CaseRunResult) -> None:
    """Print a one-line summary for a completed case."""
    if result.error:
        status = f"ERROR: {result.error[:60]}"
    elif result.evaluation:
        recall_pct = f"{result.evaluation.recall * 100:.0f}%"
        status = (
            f"recall={recall_pct} "
            f"({result.evaluation.matched_count}/{result.evaluation.reference_count} ref), "
            f"novel={result.evaluation.novel_findings_count}"
        )
    else:
        status = f"findings={len(result.findings)} (no eval)"

    print(
        f"  [{result.case_id}] {status} | {result.execution_time_seconds:.0f}s"
    )
