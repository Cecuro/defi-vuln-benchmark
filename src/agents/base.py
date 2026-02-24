"""Base agent interface for DVBench — DeFi Vulnerability Finding Benchmark.

All agents must subclass BaseAgent and implement the run() method.
Register new agents in src/agents/__init__.py.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from pydantic import BaseModel


class AgentFinding(BaseModel):
    """A vulnerability finding reported by an agent via the report_finding tool."""

    title: str
    severity: Literal["critical", "high", "medium", "low", "informational"]
    description: str
    location: str = ""        # optional: file path, function name, or line range
    recommendation: str = ""  # optional: suggested fix


class BaseAgent(ABC):
    """Abstract base class for all benchmark agents.

    To add a new agent:
    1. Create a new directory under src/agents/your_agent/
    2. Subclass BaseAgent and implement run()
    3. Register it in src/agents/__init__.py: AGENTS["your_agent"] = YourAgent
    4. Run with: uv run python cli.py pentest --agent your_agent
    """

    name: str = "base"  # override in subclass

    @abstractmethod
    async def run(
        self,
        working_dir: Path,
        challenge: dict,
        config: "BenchmarkConfig",  # type: ignore[name-defined]  # noqa: F821
    ) -> list[AgentFinding]:
        """Run the agent on a single challenge.

        Args:
            working_dir: Foundry project directory with contracts/ subdirectory.
            challenge:   Raw case dict from cases.jsonl (includes target_contract,
                         chain_id, block_number, reference_findings, etc.)
            config:      Benchmark configuration.

        Returns:
            List of AgentFinding objects reported by the agent.
        """
        ...
