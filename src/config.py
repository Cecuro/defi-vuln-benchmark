"""Configuration for DVBench — DeFi Vulnerability Finding Benchmark."""

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BenchmarkConfig:
    """Configuration for the benchmark pipeline.

    All values can be overridden via environment variables or CLI flags.
    """

    # ── Model (Azure OpenAI) ──────────────────────────────────────────────────
    model_deployment: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
    )
    model_api_version: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_API_VERSION", "2025-03-01-preview")
    )
    model_timeout: float = 240.0
    reasoning_effort: str = "high"  # high matches internal baseline

    # ── Agent limits ──────────────────────────────────────────────────────────
    time_limit_minutes: float = 60.0
    time_limit_warning_threshold: float = 0.85  # warn agent at 85% of budget
    max_iterations: int = 500  # langgraph recursion_limit

    # ── Dataset ───────────────────────────────────────────────────────────────
    dataset_path: Path = field(default_factory=lambda: Path("data/cases.jsonl"))
    cache_dir: Path = field(default_factory=lambda: Path(".cache/etherscan"))

    # ── Output ────────────────────────────────────────────────────────────────
    working_dir: Path = field(default_factory=lambda: Path("workspace"))
    skip_foundry: bool = False
    run_evaluation: bool = True

    # ── Evaluation judge ─────────────────────────────────────────────────────
    judge_deployment: str = field(
        default_factory=lambda: os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5.1")
    )


# Chain ID → RPC env var name (same mapping as internal pipeline)
RPC_ENV_VARS: dict[int, str] = {
    1: "ETH_RPC_URL",
    56: "BSC_RPC_URL",
    8453: "BASE_RPC_URL",
    137: "POLYGON_RPC_URL",
    42161: "ARBITRUM_RPC_URL",
    10: "OPTIMISM_RPC_URL",
    43114: "AVALANCHE_RPC_URL",
}


def get_rpc_url(chain_id: int) -> str:
    """Get RPC URL for a chain from environment variables."""
    env_var = RPC_ENV_VARS.get(chain_id, "ETH_RPC_URL")
    rpc_url = os.getenv(env_var)
    if not rpc_url:
        raise ValueError(
            f"RPC URL not configured for chain {chain_id}. Set {env_var} in your .env file."
        )
    return rpc_url
