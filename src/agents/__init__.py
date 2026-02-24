"""Agent registry for DVBench — DeFi Vulnerability Finding Benchmark.

To add a new agent:
1. Create src/agents/your_agent/ with an agent class subclassing BaseAgent
2. Add an entry to AGENTS below
3. Run with: uv run python cli.py pentest --agent your_agent

See src/agents/base.py for the BaseAgent interface and src/agents/baseline/
for a complete reference implementation.
"""

from .base import AgentFinding, BaseAgent
from .baseline import BaselineAgent

AGENTS: dict[str, type[BaseAgent]] = {
    "baseline": BaselineAgent,
}


def get_agent(name: str) -> type[BaseAgent]:
    """Look up an agent class by name."""
    if name not in AGENTS:
        available = ", ".join(sorted(AGENTS))
        raise ValueError(f"Unknown agent '{name}'. Available: {available}")
    return AGENTS[name]


__all__ = ["BaseAgent", "AgentFinding", "BaselineAgent", "AGENTS", "get_agent"]
