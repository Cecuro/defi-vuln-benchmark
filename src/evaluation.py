"""LLM-as-judge evaluation for the DeFi vulnerability finding benchmark.

Computes per-case recall: what fraction of the auditable reference findings
did the agent identify? Also tracks novel findings (agent findings that do
not match any reference finding).

The judge is a single structured LLM call per reference finding.
"""

import json
import os
from dataclasses import dataclass, field

from langchain_openai import AzureChatOpenAI

from .agents.base import AgentFinding
from .config import BenchmarkConfig

# ── Judge prompt ──────────────────────────────────────────────────────────────

JUDGE_SYSTEM_PROMPT = """You are a senior smart contract security researcher evaluating audit quality.

Your task: determine whether a set of agent-reported findings covers a specific reference vulnerability.

You will be given:
1. A reference finding (the vulnerability that should have been found)
2. A list of agent findings (what the agent actually reported)

Respond with valid JSON only:
{"matched": true/false, "matched_finding_title": "...", "reasoning": "..."}

- matched: true if ANY agent finding substantially covers the same root cause as the reference
- matched_finding_title: the title of the matching agent finding (or null if no match)
- reasoning: 1-2 sentences explaining your decision

Rules:
- Match on ROOT CAUSE, not exact wording. The agent may describe the same vulnerability differently.
- Do NOT match if the agent finding only tangentially mentions the issue.
- Do NOT require the agent to use the exact same title or severity.
- A finding DOES match even if the agent missed some details, as long as the core flaw is identified."""

JUDGE_USER_TEMPLATE = """## Reference Finding (should have been found)

Title: {ref_title}
Severity: {ref_severity}
Description:
{ref_content}

---

## Agent Findings (what was actually reported)

{agent_findings_text}

---

Does any agent finding identify the same root cause as the reference finding?
Respond with JSON: {{"matched": true/false, "matched_finding_title": "...", "reasoning": "..."}}"""


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass
class FindingMatchResult:
    """Result of matching one reference finding against agent findings."""

    reference_title: str
    reference_severity: str
    matched: bool
    matched_agent_finding: str | None
    reasoning: str


@dataclass
class CaseEvalResult:
    """Evaluation result for a single benchmark case."""

    case_id: str
    recall: float  # matched / total auditable reference findings
    reference_count: int  # number of auditable reference findings
    matched_count: int  # number of reference findings matched by agent
    novel_findings_count: int  # agent findings not matching any reference
    match_details: list[FindingMatchResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "recall": self.recall,
            "reference_count": self.reference_count,
            "matched_count": self.matched_count,
            "novel_findings_count": self.novel_findings_count,
            "match_details": [
                {
                    "reference_title": m.reference_title,
                    "reference_severity": m.reference_severity,
                    "matched": m.matched,
                    "matched_agent_finding": m.matched_agent_finding,
                    "reasoning": m.reasoning,
                }
                for m in self.match_details
            ],
        }


# ── Judge helpers ──────────────────────────────────────────────────────────────


def _make_judge_model(config: BenchmarkConfig) -> AzureChatOpenAI:
    return AzureChatOpenAI(
        azure_deployment=config.judge_deployment,
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=config.model_api_version,
        timeout=60.0,
        use_responses_api=True,
        reasoning={"effort": "low", "summary": "auto"},
    )


def _format_agent_findings(agent_findings: list[AgentFinding]) -> str:
    if not agent_findings:
        return "(no findings reported)"
    lines = []
    for i, f in enumerate(agent_findings, 1):
        lines.append(f"### Finding {i}: [{f.severity.upper()}] {f.title}")
        lines.append(f"Location: {f.location or '(not specified)'}")
        lines.append(f"Description: {f.description}")
        if f.recommendation:
            lines.append(f"Recommendation: {f.recommendation}")
        lines.append("")
    return "\n".join(lines)


async def _judge_single_finding(
    ref_finding: dict,
    agent_findings: list[AgentFinding],
    model: AzureChatOpenAI,
) -> FindingMatchResult:
    """Ask the LLM judge whether any agent finding matches a reference finding."""
    agent_text = _format_agent_findings(agent_findings)

    user_msg = JUDGE_USER_TEMPLATE.format(
        ref_title=ref_finding.get("title", ""),
        ref_severity=ref_finding.get("severity", ""),
        ref_content=ref_finding.get("content", ""),
        agent_findings_text=agent_text,
    )

    try:
        response = await model.ainvoke(
            [
                {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ]
        )
        raw = response.content
        if isinstance(raw, list):
            raw = " ".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in raw)

        # Extract JSON from response
        raw = raw.strip()
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start >= 0 and end > start:
            raw = raw[start:end]

        data = json.loads(raw)
        return FindingMatchResult(
            reference_title=ref_finding.get("title", ""),
            reference_severity=ref_finding.get("severity", ""),
            matched=bool(data.get("matched", False)),
            matched_agent_finding=data.get("matched_finding_title"),
            reasoning=data.get("reasoning", ""),
        )
    except Exception as e:
        return FindingMatchResult(
            reference_title=ref_finding.get("title", ""),
            reference_severity=ref_finding.get("severity", ""),
            matched=False,
            matched_agent_finding=None,
            reasoning=f"Judge error: {e}",
        )


# ── Main evaluation function ───────────────────────────────────────────────────


async def evaluate_case(
    case_id: str,
    agent_findings: list[AgentFinding],
    reference_findings: list[dict],
    config: BenchmarkConfig,
) -> CaseEvalResult:
    """Evaluate agent findings against reference findings using LLM-as-judge.

    Only evaluates reference findings where auditable=True.

    Args:
        case_id:            Case identifier for logging.
        agent_findings:     Findings reported by the agent.
        reference_findings: Reference findings from cases.jsonl.
        config:             Benchmark configuration.

    Returns:
        CaseEvalResult with recall, match details, and novel finding count.
    """
    # Filter to auditable reference findings only
    auditable = [f for f in reference_findings if f.get("auditable", True)]

    if not auditable:
        return CaseEvalResult(
            case_id=case_id,
            recall=1.0,  # nothing to find → trivially recalled
            reference_count=0,
            matched_count=0,
            novel_findings_count=len(agent_findings),
        )

    if not agent_findings:
        return CaseEvalResult(
            case_id=case_id,
            recall=0.0,
            reference_count=len(auditable),
            matched_count=0,
            novel_findings_count=0,
            match_details=[
                FindingMatchResult(
                    reference_title=f.get("title", ""),
                    reference_severity=f.get("severity", ""),
                    matched=False,
                    matched_agent_finding=None,
                    reasoning="Agent reported no findings.",
                )
                for f in auditable
            ],
        )

    model = _make_judge_model(config)

    # Judge each auditable reference finding independently
    import asyncio

    match_tasks = [
        _judge_single_finding(ref, agent_findings, model) for ref in auditable
    ]
    match_details = await asyncio.gather(*match_tasks)
    match_details = list(match_details)

    matched_count = sum(1 for m in match_details if m.matched)
    matched_titles = {m.matched_agent_finding for m in match_details if m.matched_agent_finding}

    # Novel findings: agent findings not cited by any match
    novel_count = sum(
        1
        for f in agent_findings
        if f.title not in matched_titles
    )

    recall = matched_count / len(auditable) if auditable else 1.0

    return CaseEvalResult(
        case_id=case_id,
        recall=recall,
        reference_count=len(auditable),
        matched_count=matched_count,
        novel_findings_count=novel_count,
        match_details=match_details,
    )
