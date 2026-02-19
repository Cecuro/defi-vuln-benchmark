#!/usr/bin/env python3
"""Enrich benchmark cases with LLM-generated reference findings.

Uses a 2+1 LLM council (default: GPT-5.2):
  Analyst 1: Full context (contract source + DeFiHackLabs PoC) → accurate root cause
  Analyst 2: Code-only (contract source, no PoC)               → detectability signal
  Judge:     Synthesises both → structured reference findings

The output is written back to data/cases.jsonl, adding reference_findings
and enrichment_metadata to each case.

Usage:
    uv run python scripts/3_enrich_cases.py
    uv run python scripts/3_enrich_cases.py --concurrency 10 --resume
    uv run python scripts/3_enrich_cases.py --after 2024-09-30
    uv run python scripts/3_enrich_cases.py --model gpt-5.1
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from langchain_openai import AzureChatOpenAI

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.etherscan import _load_from_cache  # noqa: E402

CASES_PATH = Path("data/cases.jsonl")
CACHE_DIR = Path(".cache/etherscan")

VALID_FOCUS_AREAS = [
    "access_control",
    "arithmetic",
    "asset_management",
    "business_logic",
    "compliance_governance",
    "economic_attacks",
    "execution_flow",
    "input_validation",
    "oracle_manipulation",
    "reentrancy",
    "semantic_verification",
    "supply_chain",
    "upgradeable_contracts",
]

# ── Prompts ────────────────────────────────────────────────────────────────────

ANALYST_1_PROMPT = """You are a smart contract security researcher analyzing a real-world exploit.

## Contract Source Code
{source_code}

## Exploit PoC Code
{poc_code}

## Task
This contract was exploited in a real DeFi hack. Given the contract source and the exploit
proof-of-concept, describe the vulnerability.

Focus on the ROOT CAUSE in the contract — what's wrong with the code and why it's exploitable.

For each distinct vulnerability (if the exploit chains multiple):
1. title: Concise vulnerability title (e.g., "Unchecked msg.value reuse in loop")
2. severity: critical, high, medium, or low
3. affected_functions: list of function names affected
4. root_cause: Detailed description (~200 words)
5. fix: Specific code change needed

Output valid JSON:
```json
{{"findings": [{{"title": "...", "severity": "...", "affected_functions": ["..."], "root_cause": "...", "fix": "..."}}]}}
```"""

ANALYST_2_PROMPT = """You are a smart contract security auditor. Review this contract for security vulnerabilities.

## Contract Source Code
{source_code}

## Task
Identify the most critical security vulnerabilities. For each:
1. title: Concise vulnerability title
2. severity: critical, high, medium, or low
3. affected_functions: list of affected function names
4. root_cause: Detailed description (~200 words)
5. fix: Specific code change to fix it

Focus on exploitable vulnerabilities. Prioritise by severity.

Output valid JSON:
```json
{{"findings": [{{"title": "...", "severity": "...", "affected_functions": ["..."], "root_cause": "...", "fix": "..."}}]}}
```"""

JUDGE_PROMPT = """You are a senior smart contract security researcher. Produce the audit finding(s)
that, if included in a security report BEFORE the hack, would have caused the team to fix the code.

## Analyst 1 (had contract source + exploit PoC — use as ground truth):
{analyst_1_output}

## Analyst 2 (had contract source only, no exploit info):
{analyst_2_output}

## Instructions

Analyst 1 knows what was actually exploited. Use Analyst 1 as ground truth for WHAT the vulnerability is.

Analyst 2 reviewed the code without knowing the exploit. When Analyst 2 found the SAME root cause as
Analyst 1, prefer Analyst 2's wording — it naturally reads like an audit report. When they differ,
use Analyst 1's root cause but rewrite it as an auditor would.

**Output 1-2 findings maximum.** Only include distinct root causes that enabled the exploit.

For each finding:
1. title: Describe the CODE FLAW, not the exploit technique. Auditor style.
   Example: "mint() uses spot reserves as price oracle" — NOT "attacker flash-loans to manipulate price"
2. severity: critical / high / medium / low
3. content: Root cause (~200 words). An auditor should understand the risk without knowing the exploit.
4. fix_description: Specific code change needed
5. focus_areas: 1-2 from: {focus_areas}
6. auditable: true if a code auditor could find this from source alone. false ONLY for: social
   engineering, off-chain state dependencies, admin key compromise with no code indicator.

Also output:
- code_visible: true/false — did Analyst 2 independently find the same root cause as Analyst 1?

Output valid JSON:
```json
{{"findings": [{{"title": "...", "severity": "...", "content": "...", "fix_description": "...", "focus_areas": ["..."], "auditable": true}}], "code_visible": true}}
```"""


# ── Helpers ────────────────────────────────────────────────────────────────────


def load_cases() -> list[dict]:
    cases: list[dict] = []
    with open(CASES_PATH) as f:
        for line in f:
            line = line.strip()
            if line:
                cases.append(json.loads(line))
    return cases


def save_cases(cases: list[dict]) -> None:
    CASES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CASES_PATH, "w") as f:
        for case in cases:
            f.write(json.dumps(case) + "\n")


def get_source_text(case: dict) -> str | None:
    source = _load_from_cache(case["target_contract"], case["chain_id"], CACHE_DIR)
    if not source:
        return None
    parts = []
    for path, content in sorted(source.source_files.items()):
        if path.endswith(".sol"):
            parts.append(f"// === {path} ===\n{content}")
    return "\n\n".join(parts) if parts else None


async def fetch_poc(url: str) -> str | None:
    if not url:
        return None
    raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(raw_url)
            resp.raise_for_status()
            return resp.text
    except Exception:
        return None


def truncate(text: str, max_chars: int = 120_000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n// ... (truncated)"


async def call_llm(model: AzureChatOpenAI, prompt: str) -> str:
    response = await model.ainvoke([{"role": "user", "content": prompt}])
    content = response.content
    if isinstance(content, list):
        content = " ".join(
            c.get("text", "") if isinstance(c, dict) else str(c) for c in content
        )
    # Extract JSON from response
    content = content.strip()
    start = content.find("{")
    end = content.rfind("}") + 1
    if start >= 0 and end > start:
        return content[start:end]
    return content


async def enrich_case(case: dict, model: AzureChatOpenAI) -> dict:
    case_id = case["id"]

    source_text = get_source_text(case)
    if not source_text:
        print(f"  [{case_id}] SKIP (no cached source)")
        return {
            **case,
            "source_available": False,
            "status": "source_unavailable",
            "reference_findings": [],
            "enrichment_metadata": None,
        }

    source_text = truncate(source_text)
    poc_text = (await fetch_poc(case.get("defihacklabs_url", ""))) or "(PoC not available)"

    print(f"  [{case_id}] Running council...")

    a1 = await call_llm(model, ANALYST_1_PROMPT.format(source_code=source_text, poc_code=poc_text))
    a2 = await call_llm(model, ANALYST_2_PROMPT.format(source_code=source_text))
    judge_raw = await call_llm(
        model,
        JUDGE_PROMPT.format(
            analyst_1_output=a1,
            analyst_2_output=a2,
            focus_areas=", ".join(VALID_FOCUS_AREAS),
        ),
    )

    try:
        judge_data = json.loads(judge_raw)
    except json.JSONDecodeError:
        print(f"  [{case_id}] ERROR: Judge returned invalid JSON")
        return {
            **case,
            "source_available": True,
            "status": "error",
            "reference_findings": [],
            "enrichment_metadata": {
                "model": model.azure_deployment,
                "timestamp": datetime.now(UTC).isoformat(),
                "error": "invalid JSON from judge",
            },
        }

    findings = judge_data.get("findings", [])
    reference_findings = []
    for i, f in enumerate(findings[:2]):
        focus_areas = [fa for fa in f.get("focus_areas", []) if fa in VALID_FOCUS_AREAS]
        if not focus_areas:
            focus_areas = ["business_logic"]
        reference_findings.append(
            {
                "title": f.get("title", f"Finding {i}"),
                "severity": f.get("severity", "high"),
                "content": f.get("content", f.get("root_cause", "")),
                "fix_description": f.get("fix_description", f.get("fix", "")),
                "focus_areas": focus_areas,
                "auditable": f.get("auditable", True),
            }
        )

    has_auditable = any(f.get("auditable", True) for f in reference_findings)
    status = "ready" if has_auditable else "not_auditable"

    print(
        f"  [{case_id}] OK — {len(reference_findings)} findings, "
        f"code_visible={judge_data.get('code_visible')}"
    )

    return {
        **case,
        "source_available": True,
        "status": status,
        "reference_findings": reference_findings,
        "enrichment_metadata": {
            "model": model.azure_deployment,
            "timestamp": datetime.now(UTC).isoformat(),
            "code_visible": judge_data.get("code_visible", False),
        },
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich benchmark cases with reference findings")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--resume", action="store_true", help="Skip already-enriched cases")
    parser.add_argument("--after", type=str, default=None, metavar="YYYY-MM-DD")
    parser.add_argument("--model", type=str, default="gpt-5.2")
    args = parser.parse_args()

    cutoff_ts: int | None = None
    if args.after:
        cutoff_ts = int(datetime.strptime(args.after, "%Y-%m-%d").timestamp())

    cases = load_cases()
    print(f"Loaded {len(cases)} cases from {CASES_PATH}")

    model = AzureChatOpenAI(
        azure_deployment=args.model,
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2025-03-01-preview"),
        timeout=120.0,
        use_responses_api=True,
        reasoning={"effort": "medium", "summary": "auto"},
    )

    sem = asyncio.Semaphore(args.concurrency)
    enriched: dict[str, dict] = {}

    # Build index of already-enriched cases
    if args.resume:
        for case in cases:
            if case.get("reference_findings") is not None:
                enriched[case["id"]] = case

    eligible = []
    for case in cases:
        if args.resume and case["id"] in enriched:
            continue
        if cutoff_ts and case.get("exploit_timestamp", 0) < cutoff_ts:
            enriched[case["id"]] = case
            continue
        eligible.append(case)

    print(f"{len(eligible)} cases to enrich, {len(enriched)} skipped")

    async def bounded(case: dict) -> tuple[str, dict]:
        async with sem:
            try:
                result = await enrich_case(case, model)
                return case["id"], result
            except Exception as e:
                print(f"  [{case['id']}] ERROR: {e}")
                return case["id"], {
                    **case,
                    "source_available": True,
                    "status": "error",
                    "reference_findings": [],
                    "enrichment_metadata": {
                        "model": args.model,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "error": str(e),
                    },
                }

    results = await asyncio.gather(*(bounded(c) for c in eligible))
    for case_id, result in results:
        enriched[case_id] = result

    # Preserve original order
    ordered = []
    enriched_by_id = dict(enriched)
    for case in cases:
        ordered.append(enriched_by_id.get(case["id"], case))

    save_cases(ordered)

    status_counts: dict[str, int] = {}
    for case in ordered:
        s = case.get("status", "unknown")
        status_counts[s] = status_counts.get(s, 0) + 1

    print(f"\n{'=' * 60}")
    print(f"Enrichment complete: {len(ordered)} cases")
    for status, count in sorted(status_counts.items()):
        print(f"  {status}: {count}")
    print(f"Output: {CASES_PATH}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(main())
