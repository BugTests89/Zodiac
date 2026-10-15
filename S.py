import os
import csv
import json
import time
import requests

from pathlib import Path
from datetime import datetime, timezone


# ==================================================
# Configuration
# ==================================================

RPC_URL = os.getenv(
    "https://bnb-mainnet.g.alchemy.com/v2/y2I2hJ5lSSEqfmR_5ISaF",
    "https://bsc-dataseed.binance.org/"
)

TARGET_IMPLEMENTATION = (
    "0x9646fDAD06d3e24444381f44362a3B0eB343D337"
).lower()

# Start scanning from this block.
# Set to 0 to scan from the earliest block supported
# by your RPC, which may be impractical.
START_BLOCK = int(os.getenv("START_BLOCK", "1"))

# Maximum blocks processed per execution.
# This limits each run, not the total scan.
MAX_BLOCKS_PER_RUN = int(
    os.getenv("MAX_BLOCKS_PER_RUN", "100")
)

BLOCK_BATCH_SIZE = 1
REQUEST_DELAY = 0.15
REQUEST_TIMEOUT = 30
MAX_RETRIES = 5

OUTPUT_DIR = Path("bsc_scan_results")
OUTPUT_DIR.mkdir(exist_ok=True)

PROXIES_CSV = OUTPUT_DIR / "proxies.csv"
PROXIES_JSON = OUTPUT_DIR / "proxies.json"
PROGRESS_FILE = OUTPUT_DIR / "progress.json"
SEEN_FILE = OUTPUT_DIR / "seen_contracts.json"

SESSION = requests.Session()
SESSION.headers.update({
    "Content-Type": "application/json",
    "User-Agent": "BSC-Proxy-Scanner/1.0"
})


# ==================================================
# RPC
# ==================================================

def rpc(method, params=None):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or []
    }

    for attempt in range(MAX_RETRIES):
        try:
            response = SESSION.post(
                RPC_URL,
                json=payload,
                timeout=REQUEST_TIMEOUT
            )

            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise RuntimeError(
                    f"RPC error: {data['error']}"
                )

            return data["result"]

        except Exception as exc:
            if attempt == MAX_RETRIES - 1:
                raise RuntimeError(
                    f"{method} failed after retries: {exc}"
                ) from exc

            time.sleep(min(2 ** attempt, 15))


def get_block_number():
    return int(rpc("eth_blockNumber"), 16)


def get_block(block_number):
    return rpc(
        "eth_getBlockByNumber",
        [hex(block_number), True]
    )


def get_code(address, block_number="latest"):
    return rpc(
        "eth_getCode",
        [address, block_number]
    )


def get_storage_at(address, slot, block_number="latest"):
    return rpc(
        "eth_getStorageAt",
        [address, slot, block_number]
    )


# ==================================================
# Proxy storage slots
# ==================================================

# EIP-1967 implementation slot
IMPLEMENTATION_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076"
    "cc3735a920a3ca505d382bbc"
)

# EIP-1967 beacon slot
BEACON_SLOT = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)

# EIP-1967 admin slot
ADMIN_SLOT = (
    "0xb53127684a568b3173ae13b9f8a6016e01900000"
    "0000000000000000000000"
)

# EIP-1967 admin slot is defined as:
# bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
# The exact slot is calculated below to avoid transcription errors.


def eip1967_slot(label):
    try:
        from Crypto.Hash import keccak
    except ImportError:
        return None

    k = keccak.new(digest_bits=256)
    k.update(label.encode())
    value = int.from_bytes(k.digest(), "big") - 1

    return "0x" + value.to_bytes(32, "big").hex()


def extract_address(storage_value):
    if not storage_value:
        return None

    value = storage_value.lower().replace("0x", "")

    if len(value) < 40:
        return None

    address = "0x" + value[-40:]

    if int(address[2:], 16) == 0:
        return None

    return address


def check_implementation_slot(address, block_number):
    value = get_storage_at(
        address,
        IMPLEMENTATION_SLOT,
        hex(block_number)
    )

    implementation = extract_address(value)

    if implementation == TARGET_IMPLEMENTATION:
        return {
            "type": "EIP1967_IMPLEMENTATION",
            "implementation": implementation
        }

    return None


def check_beacon_slot(address, block_number):
    value = get_storage_at(
        address,
        BEACON_SLOT,
        hex(block_number)
    )

    beacon = extract_address(value)

    if not beacon:
        return None

    try:
        # implementation() selector = 0x5c60da1b
        result = rpc(
            "eth_call",
            [
                {
                    "to": beacon,
                    "data": "0x5c60da1b"
                },
                hex(block_number)
            ]
        )

        implementation = extract_address(result)

        if implementation == TARGET_IMPLEMENTATION:
            return {
                "type": "EIP1967_BEACON",
                "beacon": beacon,
                "implementation": implementation
            }

    except Exception:
        pass

    return None


# ==================================================
# Persistent state
# ==================================================

def load_json(path, default):
    if not path.exists():
        return default

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return default


def save_json(path, data):
    temp_path = path.with_suffix(path.suffix + ".tmp")

    with temp_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    temp_path.replace(path)


def load_seen():
    data = load_json(SEEN_FILE, [])
    return set(data)


def load_progress():
    return load_json(PROGRESS_FILE, {})


def save_progress(block_number):
    save_json(PROGRESS_FILE, {
        "target_implementation": TARGET_IMPLEMENTATION,
        "last_processed_block": block_number,
        "updated_at": datetime.now(
            timezone.utc
        ).isoformat()
    })


# ==================================================
# Output
# ==================================================

def save_result(result):
    existing = load_json(PROXIES_JSON, [])

    if any(
        item["address"].lower() == result["address"].lower()
        for item in existing
    ):
        return

    existing.append(result)
    save_json(PROXIES_JSON, existing)

    file_exists = PROXIES_CSV.exists()

    with PROXIES_CSV.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "address",
                "type",
                "implementation",
                "beacon",
                "creation_block",
                "checked_block"
            ]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "address": result["address"],
            "type": result["type"],
            "implementation": result.get("implementation", ""),
            "beacon": result.get("beacon", ""),
            "creation_block": result.get("creation_block", ""),
            "checked_block": result.get("checked_block", "")
        })


# ==================================================
# Scanner
# ==================================================

def scan_contract(address, block_number, creation_block):
    try:
        code = get_code(address, hex(block_number))

        if not code or code == "0x":
            return

        result = check_implementation_slot(
            address,
            block_number
        )

        if result is None:
            result = check_beacon_slot(
                address,
                block_number
            )

        if result:
            record = {
                "address": address,
                "type": result["type"],
                "implementation": result["implementation"],
                "beacon": result.get("beacon", ""),
                "creation_block": creation_block,
                "checked_block": block_number
            }

            save_result(record)

            print(
                "[MATCH]",
                address,
                result["type"],
                result["implementation"]
            )

    except Exception as exc:
        print(f"[ERROR] {address}: {exc}")


def main():
    chain_id = int(rpc("eth_chainId"), 16)

    if chain_id != 56:
        raise RuntimeError(
            f"Wrong network: chain ID {chain_id}; expected 56."
        )

    latest_block = get_block_number()

    progress = load_progress()
    seen = load_seen()

    if progress:
        start_block = int(
            progress.get("last_processed_block", START_BLOCK - 1)
        ) + 1
    else:
        start_block = START_BLOCK

    end_block = min(
        latest_block,
        start_block + MAX_BLOCKS_PER_RUN - 1
    )

    print("Network: BNB Smart Chain Mainnet")
    print("Target:", TARGET_IMPLEMENTATION)
    print("Latest block:", latest_block)
    print("Scanning:", start_block, "->", end_block)
    print("Previously seen contracts:", len(seen))

    for block_number in range(start_block, end_block + 1):
        try:
            block = get_block(block_number)

            if not block:
                print("[WARN] Empty block:", block_number)
                continue

            for tx in block.get("transactions", []):
                # Contract creation transactions have no "to".
                if tx.get("to") is not None:
                    continue

                receipt = rpc(
                    "eth_getTransactionReceipt",
                    [tx["hash"]]
                )

                if not receipt:
                    continue

                address = receipt.get("contractAddress")

                if not address:
                    continue

                address = address.lower()

                if address in seen:
                    continue

                seen.add(address)

                scan_contract(
                    address,
                    block_number,
                    block_number
                )

                time.sleep(REQUEST_DELAY)

            save_json(SEEN_FILE, sorted(seen))
            save_progress(block_number)

            if block_number % 10 == 0:
                print(
                    f"[PROGRESS] Block {block_number}/{end_block}; "
                    f"contracts tracked: {len(seen)}"
                )

        except KeyboardInterrupt:
            save_json(SEEN_FILE, sorted(seen))
            save_progress(block_number - 1)
            print("\nStopped. Progress saved.")
            return

        except Exception as exc:
            print(
                f"[ERROR] Block {block_number}: {exc}"
            )
            print("Stopping to avoid skipping this block.")
            save_json(SEEN_FILE, sorted(seen))
            save_progress(block_number - 1)
            return

    print("\nScan batch completed.")
    print("Contracts tracked:", len(seen))
    print("Results:", PROXIES_JSON)
    print("CSV:", PROXIES_CSV)
    print("Progress:", PROGRESS_FILE)


if __name__ == "__main__":
    main()
