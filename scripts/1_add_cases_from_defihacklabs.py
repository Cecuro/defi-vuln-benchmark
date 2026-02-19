#!/usr/bin/env python3
"""Add new DeFiHackLabs exploit cases to data/cases.jsonl.

Fetches exploit .sol files from the DeFiHackLabs repo, parses chain_id,
block_number, and target_contract, then appends to data/cases.jsonl.

Note: this script adds the *base* case fields only. Run 3_enrich_cases.py
afterwards to generate reference_findings via the 2+1 LLM council.

Usage:
    uv run python scripts/1_add_cases_from_defihacklabs.py           # dry run
    uv run python scripts/1_add_cases_from_defihacklabs.py --write   # write changes
"""

import argparse
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen

CASES_FILE = Path("data/cases.jsonl")
REPO_RAW_BASE = "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main"

README_URLS = [
    f"{REPO_RAW_BASE}/README.md",
    f"{REPO_RAW_BASE}/past/2025/README.md",
    f"{REPO_RAW_BASE}/past/2024/README.md",
]

CHAIN_MAP = {
    "mainnet": 1,
    "bsc": 56,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "avalanche": 43114,
    "fantom": 250,
    "base": 8453,
    "blast": 81457,
    "gnosis": 100,
    "moonriver": 1285,
    "celo": 42220,
    "linea": 59144,
    "mantle": 5000,
    "sei": 1329,
    "sepolia": 11155111,
}

# --- README parsing ---

HEADING_RE = re.compile(r"^###\s+(\d{8})\s+(.+?)\s*$", re.MULTILINE)
LOST_RE = re.compile(
    r"^#{3,4}\s+Lost:\s*~?\s*\$?([\d,._]+)\s*([KMB](?!\w))?\s*(USD|ETH|BNB|BUSD|BTCB|DAI|WETH|WBTC)?",
    re.MULTILINE | re.IGNORECASE,
)
EVM_VERSION_RE = re.compile(r"--evm-version\s+(\w+)")

# Match file paths like src/test/2024-01/Name_exp.sol from various contexts
# Captures the YYYY-MM/filename.sol portion
FILE_PATH_RE = re.compile(r"src/test/(\d{4}-\d{2}/[A-Za-z0-9_.]+\.sol)")

# --- Solidity file parsing ---

# Match both createSelectFork and createFork
FORK_RE = re.compile(r'create(?:Select)?Fork\(\s*"(\w+)"\s*,\s*(.+?)\s*\)')
# Fallback: createFork with a variable RPC URL
FORK_VAR_RE = re.compile(r"create(?:Select)?Fork\(\s*(\w+)\s*,\s*(.+?)\s*\)")
# Resolve string constants: string constant RPC_URL = "bsc";
STR_CONST_RE = re.compile(r'(\w+)\s*=\s*"(\w+)"\s*;')
VULN_COMMENT_RE = re.compile(
    r"Vuln(?:erable)?\s+Contract\s*(?:Code)?\s*:.*?(?:address/|/|:\s*)(0x[0-9a-fA-F]{40})",
    re.IGNORECASE,
)
# Match "Vulnerable Contracts :" (plural) followed by sub-entries like "//   - Name: 0x..."
VULN_CONTRACTS_PLURAL_RE = re.compile(r"Vuln(?:erable)?\s+Contracts\s*:", re.IGNORECASE)
VULN_SUB_ENTRY_RE = re.compile(r"//\s*-\s*\w.*?(0x[0-9a-fA-F]{40})")
# Extract attacker/attack-contract addresses from comments to exclude from fallback
ATTACK_ADDR_RE = re.compile(
    r"(?:Attack(?:er|_Contract| Contract))\s*[:=].*?(0x[0-9a-fA-F]{40})",
    re.IGNORECASE,
)
ADDR_CONST_RE = re.compile(r"(0x[0-9a-fA-F]{40})")
# Match "address [constant] VAR_NAME = 0x..." to extract variable name context
ADDR_WITH_NAME_RE = re.compile(
    r"(?:address\s+(?:constant\s+|immutable\s+|public\s+|private\s+|internal\s+)*"
    r"(\w+)\s*=\s*|(\w+)\s*=\s*)"
    r"(0x[0-9a-fA-F]{40})"
)
# Variable name patterns that indicate DEX/infrastructure, not the exploit target
INFRA_VAR_PATTERNS = {
    "POOL",
    "ROUTER",
    "FACTORY",
    "PAIR",
    "FLASH",
    "LENDING",
    "AAVE",
    "PANCAKE",
    "UNI",
    "SUSHI",
    "BALANCER",
    "CURVE",
    "WETH",
    "WBNB",
}
UINT_VAR_RE = re.compile(r"(\w+)\s*=\s*(\d[\d_]*)\s*;")

# Common addresses to skip — well-known tokens, routers, and infrastructure
# that are almost never the exploit target
SKIP_ADDRS = {
    # Cheatcodes / utilities
    "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D",  # cheatcodes
    "0xCe71065D4017F316EC606Fe4422e11eB2c47c246",  # cheatcodes v2
    "0x0000000000000000000000000000000000000000",
    "0xcA11bde05977b3631167028862bE2a173976CA11",  # Multicall3
    # Wrapped native tokens
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH (Ethereum)
    "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",  # WBNB (BSC)
    "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",  # WMATIC (Polygon)
    "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",  # WETH (Arbitrum)
    "0x4200000000000000000000000000000000000006",  # WETH (Base/Optimism/Blast)
    "0x4300000000000000000000000000000000000004",  # WETH (Blast)
    # Major stablecoins (Ethereum)
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
    "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # DAI
    # Major stablecoins (BSC)
    "0x55d398326f99059fF775485246999027B3197955",  # BSC USDT
    "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",  # BSC USDC
    "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",  # BUSD
    # Major stablecoins (Base)
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",  # USDC (Base)
    # Major stablecoins (Arbitrum)
    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831",  # USDC (Arbitrum)
    "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",  # USDC.e (Arbitrum)
    "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",  # USDT (Arbitrum)
    # Common DEX routers
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",  # Uniswap V2 Router
    "0xE592427A0AEce92De3Edee1F18E0157C05861564",  # Uniswap V3 Router
    "0x10ED43C718714eb63d5aA57B78B54704E256024E",  # PancakeSwap V2 Router
    "0x13f4EA83D0bd40E75C8222255bc855a974568Dd4",  # PancakeSwap V3 Router
}


def fetch_url(url: str) -> str | None:
    """Fetch URL content, return None on 404."""
    try:
        with urlopen(url) as resp:
            return resp.read().decode("utf-8")
    except HTTPError as e:
        if e.code == 404:
            return None
        raise


def parse_readmes(readmes: list[str]) -> dict[str, dict]:
    """Parse README content into entries keyed by canonical file path.

    Keys are like "src/test/2024-01/CitadelFinance_exp.sol".
    """
    entries: dict[str, dict] = {}

    for readme in readmes:
        sections = HEADING_RE.split(readme)
        i = 1
        while i + 2 < len(sections):
            date_str = sections[i]
            heading_rest = sections[i + 1]
            body = sections[i + 2]
            i += 3

            # Parse heading: "ProjectName - Vuln Type"
            parts = heading_rest.split(" - ", 1)
            name = parts[0].strip()
            vuln_type = parts[1].strip() if len(parts) > 1 else None

            # Extract all file paths from body (both links and forge commands)
            file_paths = FILE_PATH_RE.findall(body)
            if not file_paths:
                continue

            evm_match = EVM_VERSION_RE.search(body)
            evm_version = evm_match.group(1) if evm_match else None

            # Parse lost amount
            lost_raw = None
            lost_value = None
            lost_unit = None
            lost_usd = None
            lost_match = LOST_RE.search(body)
            if lost_match:
                raw_val = lost_match.group(1).replace(",", ".").replace("_", "")
                multiplier_str = lost_match.group(2)
                unit = lost_match.group(3)
                try:
                    value = float(raw_val)
                    multiplier = {"K": 1e3, "M": 1e6, "B": 1e9}.get(
                        (multiplier_str or "").upper(), 1.0
                    )
                    value *= multiplier
                    lost_raw = lost_match.group(0).split("Lost:")[-1].strip()
                    lost_value = value
                    lost_unit = (unit or "USD").upper()
                    if lost_unit == "USD":
                        lost_usd = value
                except ValueError:
                    pass

            entry = {
                "date": date_str,
                "name": name,
                "vuln_type": vuln_type,
                "evm_version": evm_version,
                "lost_amount_raw": lost_raw,
                "lost_amount_value": lost_value,
                "lost_amount_unit": lost_unit,
                "lost_amount_usd": lost_usd,
            }

            # Register under each file path found
            for fp in file_paths:
                canonical = f"src/test/{fp}"
                entries[canonical] = entry

    return entries


def resolve_block_number(expr: str, source: str, depth: int = 0) -> int | None:
    """Resolve a block number expression from Solidity source."""
    if depth > 3:
        return None
    expr = expr.strip()

    # Direct numeric literal (possibly with underscores)
    cleaned = expr.replace("_", "")
    if cleaned.isdigit():
        return int(cleaned)

    # Simple arithmetic with literals: 123456 - 1
    arith = re.match(r"(\d[\d_]*)\s*([+-])\s*(\d[\d_]*)", expr)
    if arith:
        a = int(arith.group(1).replace("_", ""))
        op = arith.group(2)
        b = int(arith.group(3).replace("_", ""))
        return a + b if op == "+" else a - b

    # Variable reference - resolve from source
    var_name = expr.strip()
    for m in UINT_VAR_RE.finditer(source):
        if m.group(1) == var_name:
            return int(m.group(2).replace("_", ""))

    # Chained: VAR_NAME = OTHER_VAR - 1 (expression with variable)
    var_expr_re = re.compile(rf"{re.escape(var_name)}\s*=\s*(.+?)\s*;")
    var_match = var_expr_re.search(source)
    if var_match:
        inner = var_match.group(1).strip()
        # Try resolving as VAR +/- N
        var_arith = re.match(r"(\w+)\s*([+-])\s*(\d[\d_]*)", inner)
        if var_arith:
            resolved = resolve_block_number(var_arith.group(1), source, depth + 1)
            if resolved is not None:
                b = int(var_arith.group(3).replace("_", ""))
                return resolved + b if var_arith.group(2) == "+" else resolved - b

    return None


def parse_exploit_file(source: str) -> dict:
    """Parse a Solidity exploit file to extract chain, block, and target."""
    result: dict = {
        "chain_id": None,
        "block_number": None,
        "target_contract": None,
    }

    fork_match = FORK_RE.search(source)
    if fork_match:
        chain_name = fork_match.group(1).lower()
        result["chain_id"] = CHAIN_MAP.get(chain_name)
        result["block_number"] = resolve_block_number(fork_match.group(2), source)
    else:
        # Fallback: createFork with variable RPC URL
        fork_var = FORK_VAR_RE.search(source)
        if fork_var:
            rpc_var = fork_var.group(1)
            # Resolve the string variable to a chain name
            for m in STR_CONST_RE.finditer(source):
                if m.group(1) == rpc_var:
                    chain_name = m.group(2).lower()
                    result["chain_id"] = CHAIN_MAP.get(chain_name)
                    break
            result["block_number"] = resolve_block_number(fork_var.group(2), source)

    vuln_match = VULN_COMMENT_RE.search(source)
    if vuln_match:
        result["target_contract"] = vuln_match.group(1)
    else:
        # Check for "Vulnerable Contracts :" (plural) with sub-entries
        plural_match = VULN_CONTRACTS_PLURAL_RE.search(source)
        if plural_match:
            # Look at lines after the "Vulnerable Contracts :" header
            after_header = source[plural_match.end() :]
            for line in after_header.splitlines():
                line_stripped = line.strip()
                if not line_stripped:
                    continue  # Skip empty lines
                if not line_stripped.startswith("//"):
                    break  # End of comment block
                sub_match = VULN_SUB_ENTRY_RE.match(line_stripped)
                if sub_match:
                    result["target_contract"] = sub_match.group(1)
                    break

    if not result["target_contract"]:
        # Collect attacker/attack-contract addresses from comments to exclude
        attack_addrs: set[str] = set()
        for m in ATTACK_ADDR_RE.finditer(source):
            attack_addrs.add(m.group(1).lower())

        # Strip comment lines and build address list with variable name context
        code_lines = [
            line for line in source.splitlines() if not line.lstrip().startswith("//")
        ]
        code_only = "\n".join(code_lines)

        # Build map of address -> variable name from named constants
        addr_to_var: dict[str, str] = {}
        for m in ADDR_WITH_NAME_RE.finditer(code_only):
            var_name = m.group(1) or m.group(2)
            addr = m.group(3)
            if var_name:
                addr_to_var[addr.lower()] = var_name.upper()

        # Pick first non-skip, non-attack, non-infrastructure address
        for m in ADDR_CONST_RE.finditer(code_only):
            addr = m.group(1)
            if addr in SKIP_ADDRS or addr.lower() in attack_addrs:
                continue
            var_name = addr_to_var.get(addr.lower(), "")
            if any(pat in var_name for pat in INFRA_VAR_PATTERNS):
                continue
            result["target_contract"] = addr
            break

    return result


def make_case_id(name: str) -> str:
    """Generate a clean case ID from a project name."""
    clean = re.sub(r"[^a-zA-Z0-9_\s]", "", name)
    clean = clean.strip().lower().replace(" ", "_")
    clean = re.sub(r"_+", "_", clean)
    return clean


def run(write: bool) -> None:
    # Load existing cases and build set of known file paths
    existing_paths: set[str] = set()
    existing_ids: set[str] = set()
    cases: list[dict] = []

    with open(CASES_FILE) as f:
        for line in f:
            if line.strip():
                case = json.loads(line)
                cases.append(case)
                existing_ids.add(case["id"])
                # Extract canonical path from defihacklabs_url
                url = case.get("defihacklabs_url", "")
                if "src/test/" in url:
                    path = "src/test/" + url.split("src/test/")[-1]
                    existing_paths.add(path)

    print(f"Existing cases: {len(cases)} ({len(existing_paths)} unique file paths)")

    # Fetch and parse READMEs
    print("Fetching DeFiHackLabs READMEs...")
    readmes = []
    for url in README_URLS:
        print(f"  {url.split('/main/')[-1]}")
        content = fetch_url(url)
        if content:
            readmes.append(content)

    readme_data = parse_readmes(readmes)
    print(f"  Parsed {len(readme_data)} entries from READMEs")

    # Find new entries by comparing file paths
    new_entries: dict[str, dict] = {}
    for file_path, entry in readme_data.items():
        if file_path in existing_paths:
            continue
        new_entries[file_path] = entry

    print(f"\nNew cases to add: {len(new_entries)}")

    if not new_entries:
        print("Nothing to add!")
        return

    # Fetch each exploit .sol file and parse it
    new_cases: list[dict] = []
    failures: list[tuple[str, str]] = []

    sorted_entries = sorted(new_entries.items(), key=lambda x: x[1]["date"])
    for i, (file_path, entry) in enumerate(sorted_entries):
        name = entry["name"]
        exploit_file = file_path.split("/")[-1]  # e.g., Name_exp.sol

        sol_url = f"{REPO_RAW_BASE}/{file_path}"
        print(
            f"  [{i + 1}/{len(new_entries)}] {name} ({exploit_file})...",
            end=" ",
            flush=True,
        )

        source = fetch_url(sol_url)
        if not source:
            print("SKIP (404)")
            failures.append((name, f"File not found: {file_path}"))
            continue

        parsed = parse_exploit_file(source)

        if not parsed["chain_id"] or not parsed["block_number"]:
            print(
                f"SKIP (missing chain={parsed['chain_id']} block={parsed['block_number']})"
            )
            failures.append(
                (
                    name,
                    f"Parse failed: chain={parsed['chain_id']} block={parsed['block_number']}",
                )
            )
            continue

        if not parsed["target_contract"]:
            print("SKIP (no target contract found)")
            failures.append((name, "No target contract"))
            continue

        # Generate case ID
        case_id = make_case_id(name)
        if case_id in existing_ids:
            case_id = case_id + "_v2"
        if case_id in existing_ids:
            case_id = case_id + "_" + entry["date"]
        existing_ids.add(case_id)

        dt = datetime.strptime(entry["date"], "%Y%m%d").replace(tzinfo=UTC)
        exploit_timestamp = int(dt.timestamp())

        defihacklabs_url = (
            f"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/{file_path}"
        )

        case = {
            "id": case_id,
            "name": name,
            "chain_id": parsed["chain_id"],
            "block_number": parsed["block_number"],
            "target_contract": parsed["target_contract"],
            "exploit_file": exploit_file,
            "evm_version": entry.get("evm_version"),
            "exploit_timestamp": exploit_timestamp,
            "native_token_price_usd": None,
            "defihacklabs_url": defihacklabs_url,
            "defihacklabs_vuln_type": entry.get("vuln_type"),
            "lost_amount_raw": entry.get("lost_amount_raw"),
            "lost_amount_value": entry.get("lost_amount_value"),
            "lost_amount_unit": entry.get("lost_amount_unit"),
            "lost_amount_usd": entry.get("lost_amount_usd"),
            "loss_source": "defihacklabs_readme",
            "dataset_version": "v2",
        }

        new_cases.append(case)
        date_str = datetime.fromtimestamp(exploit_timestamp, tz=UTC).strftime(
            "%Y-%m-%d"
        )
        print(
            f"OK chain={parsed['chain_id']} block={parsed['block_number']} date={date_str}"
        )

        time.sleep(0.1)

    print("\nResults:")
    print(f"  Successfully parsed: {len(new_cases)}")
    print(f"  Failed: {len(failures)}")

    if failures:
        print("\n  Failures:")
        for name, reason in failures:
            print(f"    {name}: {reason}")

    if write and new_cases:
        with open(CASES_FILE, "a") as f:
            for case in new_cases:
                f.write(json.dumps(case, ensure_ascii=False) + "\n")
        print(f"\n  Appended {len(new_cases)} cases to {CASES_FILE}")
        print(f"  Total cases: {len(cases) + len(new_cases)}")
    elif new_cases:
        print("\nSample new entries:")
        for case in new_cases[:5]:
            date = datetime.fromtimestamp(case["exploit_timestamp"], tz=UTC).strftime(
                "%Y-%m-%d"
            )
            print(
                f"  {case['id']:<30} chain={case['chain_id']:<6} date={date}  {case['defihacklabs_vuln_type']}"
            )
        if len(new_cases) > 5:
            print(f"  ... and {len(new_cases) - 5} more")
        print("\nRun with --write to save changes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Add new DeFiHackLabs cases to dataset"
    )
    parser.add_argument(
        "--write", action="store_true", help="Write changes to cases.jsonl"
    )
    args = parser.parse_args()
    run(write=args.write)
