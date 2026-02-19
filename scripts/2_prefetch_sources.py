#!/usr/bin/env python3
"""Prefetch contract sources from Etherscan for all benchmark cases.

Loads cases from data/cases.jsonl, fetches verified source code via Etherscan
V2 API, and caches results at .cache/etherscan/. Writes a source_manifest.json
summarising availability.

Run this before 3_enrich_cases.py to warm the source cache. If you commit
.cache/etherscan/ to the repo, users can run the benchmark without their own
Etherscan API key.

Usage:
    uv run python scripts/2_prefetch_sources.py
    uv run python scripts/2_prefetch_sources.py --concurrency 3 --resume
    uv run python scripts/2_prefetch_sources.py --after 2024-09-30
"""

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Add project root to path so we can import src/
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.etherscan import SUPPORTED_CHAINS, fetch_contract_source  # noqa: E402

CASES_PATH = Path("data/cases.jsonl")
MANIFEST_PATH = Path("data/source_manifest.json")
CACHE_DIR = Path(".cache/etherscan")


def load_cases(after: str | None = None) -> list[dict]:
    cutoff_ts: int | None = None
    if after:
        cutoff_ts = int(datetime.strptime(after, "%Y-%m-%d").timestamp())

    cases: list[dict] = []
    with open(CASES_PATH) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            if cutoff_ts and data.get("exploit_timestamp", 0) < cutoff_ts:
                continue
            cases.append(data)
    return cases


def load_manifest() -> dict[str, dict]:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text())
    return {}


def save_manifest(manifest: dict[str, dict]) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2))


async def prefetch_single(
    case: dict,
    api_key: str,
    manifest: dict[str, dict],
    resume: bool,
) -> dict:
    case_id = case["id"]

    if resume and case_id in manifest and manifest[case_id].get("source_available"):
        print(f"  [{case_id}] Skipping (cached)")
        return manifest[case_id]

    chain_id = case.get("chain_id", 1)
    if chain_id not in SUPPORTED_CHAINS:
        entry = {
            "case_id": case_id,
            "source_available": False,
            "error": f"Unsupported chain_id: {chain_id}",
            "source_file_count": 0,
            "total_chars": 0,
        }
        print(f"  [{case_id}] SKIP (unsupported chain {chain_id})")
        return entry

    try:
        source = await fetch_contract_source(
            address=case["target_contract"],
            chain_id=chain_id,
            api_key=api_key,
            cache_dir=CACHE_DIR,
        )
        sol_count = sum(1 for p in source.source_files if p.endswith(".sol"))
        total_chars = sum(len(c) for c in source.source_files.values())
        has_proxy = any(p.startswith("impl/") for p in source.source_files)

        entry = {
            "case_id": case_id,
            "source_available": True,
            "source_file_count": len(source.source_files),
            "total_chars": total_chars,
            "solidity_file_count": sol_count,
            "contract_name": source.name,
            "compiler_version": source.compiler_version,
            "has_proxy": has_proxy,
            "error": None,
        }
        print(
            f"  [{case_id}] OK — {len(source.source_files)} files, "
            f"{total_chars:,} chars, proxy={has_proxy}"
        )
        return entry

    except Exception as e:
        entry = {
            "case_id": case_id,
            "source_available": False,
            "error": str(e),
            "source_file_count": 0,
            "total_chars": 0,
        }
        print(f"  [{case_id}] FAILED — {e}")
        return entry


async def main() -> None:
    parser = argparse.ArgumentParser(description="Prefetch exploit contract sources")
    parser.add_argument("--concurrency", type=int, default=3)
    parser.add_argument("--after", type=str, default=None, metavar="YYYY-MM-DD")
    parser.add_argument("--resume", action="store_true", help="Skip already-cached cases")
    args = parser.parse_args()

    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    if not api_key:
        print("Error: ETHERSCAN_API_KEY not set in environment / .env")
        sys.exit(1)

    cases = load_cases(after=args.after)
    print(f"Loaded {len(cases)} cases from {CASES_PATH}")

    manifest = load_manifest() if args.resume else {}
    sem = asyncio.Semaphore(args.concurrency)

    async def bounded(case: dict) -> tuple[str, dict]:
        async with sem:
            entry = await prefetch_single(case, api_key, manifest, args.resume)
            return case["id"], entry

    results = await asyncio.gather(*(bounded(c) for c in cases), return_exceptions=True)

    for result in results:
        if isinstance(result, BaseException):
            print(f"Unexpected error: {result}")
            continue
        case_id, entry = result
        manifest[case_id] = entry

    save_manifest(manifest)

    available = sum(1 for v in manifest.values() if v.get("source_available"))
    failed = sum(1 for v in manifest.values() if not v.get("source_available"))
    print(f"\n{'=' * 60}")
    print(f"Prefetch complete: {len(manifest)} cases")
    print(f"  Source available: {available}")
    print(f"  Failed/unavailable: {failed}")
    print(f"  Cache: {CACHE_DIR}")
    print(f"  Manifest: {MANIFEST_PATH}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(main())
