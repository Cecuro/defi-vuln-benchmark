"""Baseline vulnerability identification agent.

Uses langchain.agents.create_agent with middleware for production-ready
context management, retries, and summarization.

The agent reads contract source and calls report_finding for each vulnerability.
"""

import asyncio
import os
import time
from pathlib import Path
from typing import Any

from langchain.agents import create_agent
from langchain.agents.middleware import (
    ContextEditingMiddleware,
    FilesystemFileSearchMiddleware,
    ModelRetryMiddleware,
    ShellToolMiddleware,
    SummarizationMiddleware,
    TodoListMiddleware,
    ToolRetryMiddleware,
)
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI

from src.agents.base import AgentFinding, BaseAgent
from src.config import BenchmarkConfig

from .prompts import build_system_prompt


def _make_model(config: BenchmarkConfig) -> AzureChatOpenAI:
    """Instantiate the Azure OpenAI model with high reasoning."""
    return AzureChatOpenAI(
        azure_deployment=config.model_deployment,
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=config.model_api_version,
        timeout=config.model_timeout,
        use_responses_api=True,
        reasoning={"effort": config.reasoning_effort, "summary": "auto"},
    )


def _make_tools(
    findings: list[AgentFinding],
    time_limit_seconds: float,
    start_time: float,
) -> list[Any]:
    """Create the benchmark-specific tool: report_finding.

    Shell, glob, grep, and write_todos are provided by middleware
    (ShellToolMiddleware, FilesystemFileSearchMiddleware, TodoListMiddleware)
    and scoped to the working directory there.
    """

    @tool
    def report_finding(
        title: str,
        severity: str,
        description: str,
        location: str = "",
        recommendation: str = "",
    ) -> str:
        """Report a security vulnerability finding.

        Call this for each distinct vulnerability you identify.
        Findings are saved immediately — call this as you find issues,
        not only at the end.

        Args:
            title:          Concise vulnerability title describing the code flaw.
                            Example: "mint() uses spot price without TWAP protection"
            severity:       One of: critical, high, medium, low, informational
            description:    Root cause description (~100-200 words). Explain what is
                            wrong in the code and what risk it enables.
            location:       Optional file path, function name, or line reference.
                            Example: "contracts/Token.sol, sell() function"
            recommendation: Optional fix suggestion.
        """
        severity_lower = severity.lower()
        valid = {"critical", "high", "medium", "low", "informational"}
        if severity_lower not in valid:
            severity_lower = "medium"

        finding = AgentFinding(
            title=title,
            severity=severity_lower,  # type: ignore[arg-type]
            description=description,
            location=location,
            recommendation=recommendation,
        )
        findings.append(finding)
        n = len(findings)

        elapsed = time.time() - start_time
        remaining = time_limit_seconds - elapsed
        time_note = (
            f" ({remaining:.0f}s remaining)"
            if remaining > 0
            else " (time budget exhausted)"
        )

        return (
            f"Finding #{n} recorded: [{severity_lower.upper()}] {title}{time_note}. "
            "Continue analyzing or call report_finding for more findings."
        )

    return [report_finding]


class BaselineAgent(BaseAgent):
    """Baseline agent: reads contract source and reports findings via report_finding tool.

    Uses langchain.agents.create_agent with Azure OpenAI GPT-5.1 (high reasoning).

    Tools available to the agent:
    - report_finding     : structured finding submission (custom, closure-captured)
    - shell              : persistent bash session rooted at working_dir (ShellToolMiddleware)
    - glob               : file pattern search scoped to working_dir (FilesystemFileSearchMiddleware)
    - grep               : ripgrep content search scoped to working_dir (FilesystemFileSearchMiddleware)
    - write_todos        : task planning and progress tracking (TodoListMiddleware)

    Middleware stack:
    - TodoListMiddleware            : audit task planning
    - SummarizationMiddleware       : summarize history at 50K tokens
    - ContextEditingMiddleware      : clear old tool results at 100K tokens
    - ModelRetryMiddleware          : retry transient API errors (2x, backoff)
    - ToolRetryMiddleware           : retry transient tool errors (2x, backoff)
    - FilesystemFileSearchMiddleware: glob + grep scoped to working_dir
    - ShellToolMiddleware           : persistent shell rooted at working_dir
    """

    name = "baseline"

    async def run(
        self,
        working_dir: Path,
        challenge: dict,
        config: BenchmarkConfig,
    ) -> list[AgentFinding]:
        """Run the agent and return collected findings."""
        findings: list[AgentFinding] = []
        time_limit_seconds = config.time_limit_minutes * 60
        start_time = time.time()

        model = _make_model(config)
        tools = _make_tools(findings, time_limit_seconds, start_time)
        system_prompt = build_system_prompt(config.time_limit_minutes)

        agent = create_agent(
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            middleware=[
                # ── Task planning ─────────────────────────────────────────────
                # Adds write_todos tool so the agent can plan and track which
                # contracts and functions it still needs to audit.
                TodoListMiddleware(),

                # ── Context management ────────────────────────────────────────
                # Summarize old turns when messages exceed 50K tokens.
                # Keeps the 20 most recent messages intact.
                SummarizationMiddleware(
                    model=model,
                    trigger=("tokens", 50_000),
                    keep=("messages", 20),
                ),
                # Clear old tool results (file reads, shell output) at 100K tokens.
                # Keeps the 3 most recent tool results; replaces older ones with "[cleared]".
                ContextEditingMiddleware(),

                # ── Reliability ───────────────────────────────────────────────
                # Retry transient model / tool errors (2 retries, exponential backoff).
                ModelRetryMiddleware(),
                ToolRetryMiddleware(),

                # ── Filesystem tools (scoped to working_dir) ──────────────────
                # Adds: glob (find files by pattern) + grep (ripgrep content search).
                FilesystemFileSearchMiddleware(root_path=str(working_dir)),
                # Adds: shell (persistent bash session rooted at working_dir).
                # Forge commands (forge build, forge inspect) persist state between calls.
                ShellToolMiddleware(workspace_root=working_dir),
            ],
        )

        target = challenge.get("target_contract", "unknown")
        chain_id = challenge.get("chain_id", 1)
        block_number = challenge.get("block_number", "unknown")

        initial_message = (
            f"## Vulnerability Identification Task\n\n"
            f"**Target**: `{target}`\n"
            f"**Chain ID**: {chain_id}\n"
            f"**Block**: {block_number}\n\n"
            f"Read `CHALLENGE.md` for context, then analyze all source files in "
            f"`contracts/`. Report every vulnerability you find using `report_finding`."
        )

        agent_config = {
            "recursion_limit": config.max_iterations,
        }

        try:
            await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [{"role": "user", "content": initial_message}]},
                    config=agent_config,
                ),
                timeout=time_limit_seconds,
            )
        except asyncio.TimeoutError:
            # Hard timeout — return whatever findings were collected so far
            pass
        except Exception:
            # Any other error — return findings collected so far
            pass

        return findings
