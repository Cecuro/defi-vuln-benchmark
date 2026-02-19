"""Etherscan V2 client for fetching verified contract source.

Self-contained — no internal imports. Adapted from the internal pipeline's
etherscan.py with identical logic: rate limiting, retries, proxy resolution,
and file-based caching.
"""

import asyncio
import json
import re
from pathlib import Path

import httpx
from pydantic import BaseModel

# Etherscan V2 API — single endpoint for all supported chains
ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"

# Supported chain IDs
SUPPORTED_CHAINS = {1, 56, 8453, 137, 42161, 10, 43114, 81457, 59144, 5000, 100}

# Max proxy recursion depth
_MAX_PROXY_DEPTH = 3

# Shared rate limiter: max 3 concurrent Etherscan requests
_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(3)
    return _semaphore


class ContractSource(BaseModel):
    """Verified contract source from Etherscan."""

    name: str
    compiler_version: str
    source_files: dict[str, str]  # path → content
    optimization_enabled: bool = False
    optimization_runs: int = 200
    evm_version: str | None = None
    constructor_args: str | None = None


def parse_source_code(source_code: str, contract_name: str) -> dict[str, str]:
    """Parse Etherscan source code response into a path→content dict.

    Handles four formats:
    1. Single string (single Solidity file)
    2. Double-brace JSON {{...}} (Solidity Standard JSON Input)
    3. Regular JSON array [...] (array of sources)
    4. Regular JSON object {...} (filename → {content: ...})
    """
    if not source_code:
        raise ValueError("Contract source not verified")

    # Format 2: Double-brace JSON (Solidity Standard JSON Input)
    if source_code.startswith("{{"):
        inner = source_code[1:-1]
        try:
            data = json.loads(inner)
            sources = data.get("sources", {})
            return {path: src.get("content", "") for path, src in sources.items()}
        except json.JSONDecodeError:
            pass

    # Format 3: Regular JSON array
    if source_code.startswith("["):
        try:
            data = json.loads(source_code)
            result = {}
            for item in data:
                filename = item.get("filename") or item.get("name", "Contract.sol")
                content = item.get("content") or item.get("source", "")
                result[filename] = content
            return result
        except json.JSONDecodeError:
            pass

    # Format 4: Regular JSON object (filename → {content: ...})
    if source_code.startswith("{"):
        try:
            data = json.loads(source_code)
            if isinstance(data, dict) and all(
                isinstance(v, dict) and "content" in v for v in data.values()
            ):
                return {path: src.get("content", "") for path, src in data.items()}
        except json.JSONDecodeError:
            pass

    # Format 1: Single string (raw Solidity)
    return {f"{contract_name}.sol": source_code}


def normalize_compiler_version(version: str) -> str:
    """Normalize compiler version string (e.g. v0.8.20+commit.abc → 0.8.20)."""
    version = version.lstrip("v")
    match = re.match(r"(\d+\.\d+\.\d+)", version)
    return match.group(1) if match else version


def _get_cache_path(address: str, chain_id: int, cache_dir: Path) -> Path:
    key = f"{chain_id}_{address.lower()}"
    return cache_dir / f"{key}.json"


def _load_from_cache(
    address: str, chain_id: int, cache_dir: Path
) -> ContractSource | None:
    cache_path = _get_cache_path(address, chain_id, cache_dir)
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            return ContractSource(**data)
        except Exception:
            pass
    return None


def _save_to_cache(
    address: str, chain_id: int, source: ContractSource, cache_dir: Path
) -> None:
    cache_path = _get_cache_path(address, chain_id, cache_dir)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(source.model_dump_json(indent=2))
    except Exception:
        pass


async def fetch_contract_source(
    address: str,
    chain_id: int,
    api_key: str,
    cache_dir: Path = Path(".cache/etherscan"),
    use_cache: bool = True,
    max_retries: int = 3,
    _proxy_depth: int = 0,
    _visited: set[str] | None = None,
) -> ContractSource:
    """Fetch verified contract source from Etherscan V2 API.

    Args:
        address:    Contract address (0x...)
        chain_id:   Chain ID (1=ETH, 56=BSC, 8453=Base, etc.)
        api_key:    Etherscan API key
        cache_dir:  Directory for file-based caching
        use_cache:  Whether to use cache (default: True)
        max_retries: Max retries on rate limit

    Returns:
        ContractSource with parsed source files.

    Raises:
        ValueError: If contract not verified or API error.
    """
    if use_cache:
        cached = _load_from_cache(address, chain_id, cache_dir)
        if cached:
            return cached

    if chain_id not in SUPPORTED_CHAINS:
        raise ValueError(
            f"Unsupported chain_id: {chain_id}. Supported: {sorted(SUPPORTED_CHAINS)}"
        )

    sem = _get_semaphore()
    data = None
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            async with sem, httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    ETHERSCAN_V2_API,
                    params={
                        "chainid": chain_id,
                        "module": "contract",
                        "action": "getsourcecode",
                        "address": address,
                        "apikey": api_key,
                    },
                )

                if response.status_code == 429:
                    wait_time = 2 ** (attempt + 1)
                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()
                data = response.json()

                if data.get("status") != "1":
                    message = data.get("result", "") or data.get("message", "")
                    if "rate limit" in str(message).lower() and attempt < max_retries:
                        wait_time = 2 ** (attempt + 1)
                        data = None
                        await asyncio.sleep(wait_time)
                        continue

                break

        except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
            last_error = e
            if attempt < max_retries:
                await asyncio.sleep(2 ** (attempt + 1))
            else:
                raise

    if data is None:
        raise ValueError(
            f"Failed to fetch contract source after {max_retries + 1} attempts: {last_error}"
        )

    if data.get("status") != "1":
        message = data.get("result", "") or data.get("message", "Unknown error")
        raise ValueError(f"Etherscan API error: {message}")

    result = data.get("result", [])
    if not result or not isinstance(result, list):
        raise ValueError("Unexpected Etherscan response format")

    contract_data = result[0]
    source_code = contract_data.get("SourceCode", "")
    if not source_code:
        raise ValueError(f"Contract {address} is not verified on chain {chain_id}")

    contract_name = contract_data.get("ContractName", "Contract")
    compiler_version = normalize_compiler_version(
        contract_data.get("CompilerVersion", "0.8.20")
    )
    source_files = parse_source_code(source_code, contract_name)

    # Handle proxy contracts — fetch implementation and merge sources
    if _visited is None:
        _visited = set()
    _visited.add(address.lower())

    if contract_data.get("Proxy") == "1":
        impl_address = contract_data.get("Implementation")
        if (
            impl_address
            and impl_address.lower() not in _visited
            and _proxy_depth < _MAX_PROXY_DEPTH
        ):
            try:
                impl_source = await fetch_contract_source(
                    impl_address,
                    chain_id,
                    api_key,
                    cache_dir=cache_dir,
                    use_cache=use_cache,
                    _proxy_depth=_proxy_depth + 1,
                    _visited=_visited,
                )
                for path, content in impl_source.source_files.items():
                    source_files[f"impl/{path}"] = content
                impl_tuple = tuple(int(x) for x in impl_source.compiler_version.split("."))
                curr_tuple = tuple(int(x) for x in compiler_version.split("."))
                if impl_tuple > curr_tuple:
                    compiler_version = impl_source.compiler_version
            except (ValueError, httpx.HTTPError, OSError):
                pass

    source = ContractSource(
        name=contract_name,
        compiler_version=compiler_version,
        source_files=source_files,
        optimization_enabled=contract_data.get("OptimizationUsed") == "1",
        optimization_runs=int(contract_data.get("Runs", 200)),
        evm_version=contract_data.get("EVMVersion") or None,
        constructor_args=contract_data.get("ConstructorArguments") or None,
    )

    if use_cache:
        _save_to_cache(address, chain_id, source, cache_dir)

    return source
