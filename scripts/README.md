# Dataset Pipeline Scripts

These scripts document and reproduce the full pipeline used to build `data/cases.jsonl`.
They are **self-contained** — no internal dependencies beyond standard libraries and httpx/pydantic.

## Overview

```
DeFiHackLabs README
        │
        ▼
1_add_cases_from_defihacklabs.py   →  data/cases.jsonl (base fields only)
        │
        ▼
2_prefetch_sources.py              →  .cache/etherscan/  (Etherscan source cache)
        │
        ▼
3_enrich_cases.py                  →  data/cases.jsonl (+ reference_findings)
```

## Step 1: Add Cases from DeFiHackLabs

```bash
uv run python scripts/1_add_cases_from_defihacklabs.py          # dry run
uv run python scripts/1_add_cases_from_defihacklabs.py --write  # write to data/cases.jsonl
```

Parses the [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) README(s) to discover
exploit entries, downloads each `.sol` file, and extracts:
- `chain_id` and `block_number` from `createSelectFork(...)` calls
- `target_contract` from `// Vulnerable Contract:` comments
- `lost_amount_usd` from the "Lost:" heading
- `defihacklabs_url`, `defihacklabs_vuln_type`, `evm_version`

Skips entries that are already in `data/cases.jsonl`.

## Step 2: Prefetch Contract Sources

```bash
uv run python scripts/2_prefetch_sources.py --concurrency 3
uv run python scripts/2_prefetch_sources.py --resume           # skip already-cached
```

Requires: `ETHERSCAN_API_KEY` in your `.env`.

Fetches verified source code for every case via the Etherscan V2 API and caches results
at `.cache/etherscan/{chain_id}_{address}.json`. Produces `data/source_manifest.json`
summarising availability.

**Pre-warming the cache**: if you commit `.cache/etherscan/` to the repo, users can run the
benchmark without needing their own Etherscan key.

## Step 3: Enrich Cases with Reference Findings

```bash
uv run python scripts/3_enrich_cases.py --concurrency 10
uv run python scripts/3_enrich_cases.py --resume              # skip already-enriched
```

Requires: `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_API_KEY` in your `.env`.
Uses GPT-5.2 (configurable via `--model`).

### How the 2+1 Council Works

For each case, three LLM calls are made:

**Analyst 1** (full context — source + DeFiHackLabs PoC):
Identifies the actual exploited vulnerability with maximum accuracy.
This is used as the ground-truth root cause.

**Analyst 2** (code-only — source, no PoC):
Reviews the source code without knowing the exploit. When Analyst 2 independently
finds the same vulnerability, its wording is preferred because it reads like a
natural audit finding (not an exploit description).

**Judge** (synthesis):
Combines both analysts. Uses Analyst 1 as ground truth for *what* the vulnerability
is, and Analyst 2's wording when available. Outputs 1–2 structured findings with:
- `title` — code flaw description (not exploit technique)
- `severity` — critical / high / medium / low
- `content` — ~200-word root cause description
- `fix_description` — specific code change to fix it
- `focus_areas` — 1–2 categories (e.g. business_logic, economic_attacks)
- `auditable` — whether a code reviewer could realistically find this

The `enrichment_metadata.code_visible` field records whether Analyst 2 independently
identified the same root cause as Analyst 1 (i.e. whether the bug is detectable from
source code alone without knowing the exploit).

## Case Schema

Each line in `data/cases.jsonl` is a JSON object:

```json
{
  "id": "aizpttoken",
  "name": "Aizpttoken",
  "chain_id": 56,
  "block_number": 42846997,
  "target_contract": "0xBe779D420b7D573C08EEe226B9958737b6218888",
  "defihacklabs_url": "https://github.com/...",
  "defihacklabs_vuln_type": "Wrong Price Calculation",
  "evm_version": "shanghai",
  "exploit_timestamp": 1728120829,
  "native_token_price_usd": 562.94,
  "lost_amount_usd": 20000.0,
  "dataset_version": "v1",
  "source_available": true,
  "status": "ready",
  "reference_findings": [
    {
      "title": "...",
      "severity": "critical",
      "content": "...",
      "fix_description": "...",
      "focus_areas": ["business_logic", "economic_attacks"],
      "auditable": true
    }
  ],
  "enrichment_metadata": {
    "model": "gpt-5.2",
    "timestamp": "2026-02-18T16:13:01Z",
    "code_visible": true
  }
}
```
