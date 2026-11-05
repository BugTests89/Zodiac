#!/usr/bin/env python3
"""
EVM Bytecode Forensics CLI
تحليل العقود المنشورة، استخراج معاملات المنشئ، الكشف عن البيانات المشبوهة،
مع دعم فصل الكود/البيانات، فك تشفير ABI التلقائي، والتحقق من storage.
"""

import argparse
import json
import math
import sys
from collections import Counter
from typing import Optional, Tuple, List, Dict, Any

import requests
from web3 import Web3
from pyevmasm import disassemble_all

# ---------------------------- التكوين ----------------------------
RPC_ENDPOINTS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
}

ETHERSCAN_CHAIN_IDS = {
    "ethereum": 1,
    "bsc": 56,
    "arbitrum": 42161,
    "base": 8453,
}

ENTROPY_THRESHOLD = 7.0
MIN_BLOB_LEN = 16
MIN_STRING_LEN = 8

# قائمة بيضاء موسعة لأحداث ERC20/721/DeFi الشائعة (topic0)
KNOWN_CONSTANTS = {
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",  # Transfer
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",  # Approval
    "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",  # ApprovalForAll
    "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",  # OwnershipTransferred
    "e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",  # Deposit
    "7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",  # Withdrawal
    "d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",  # Swap
    "1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1",  # Sync
}

# ---------------------------- أدوات مساعدة ----------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_printable_ascii(data: bytes) -> bool:
    if not isinstance(data, (bytes, bytearray)) or len(data) < MIN_STRING_LEN:
        return False
    try:
        return all(32 <= ord(c) < 127 for c in data.decode("ascii"))
    except UnicodeDecodeError:
        return False


def strip_cbor_metadata(bytecode: bytes) -> bytes:
    """إزالة بيانات CBOR الوصفية في نهاية Solidity (بادئة 0xa1/0xa2/0xa3)."""
    if len(bytecode) < 5:
        return bytecode
    length = int.from_bytes(bytecode[-2:], "big")
    if length == 0 or length + 2 > len(bytecode):
        return bytecode
    start = len(bytecode) - 2 - length
    if start >= 0 and bytecode[start] in (0xa1, 0xa2, 0xa3):
        return bytecode[:start]
    return bytecode


def _operand_to_bytes(ins) -> Optional[bytes]:
    op = ins.operand
    if op is None:
        return None
    if isinstance(op, (bytes, bytearray)):
        return bytes(op) if len(op) > 0 else None
    if isinstance(op, int):
        try:
            size = int(ins.name.replace("PUSH", ""))
        except ValueError:
            return None
        return op.to_bytes(size, byteorder="big") if size > 0 else None
    return None


def split_code_and_args(tail: bytes) -> Tuple[bytes, bytes]:
    """
    فصل كود EVM عن بيانات ABI في ذيل creation bytecode.
    يعيد (code_part, data_part).
    """
    if len(tail) < 10:
        return b"", tail
    try:
        ins_list = list(disassemble_all(tail[:200]))
        if not ins_list:
            return b"", tail
        # إذا بدأ الذيل بتعليمة كود نموذجية، فهو كود
        if ins_list[0].name not in ("JUMPDEST", "PUSH1", "PUSH2", "PUSH32", "PUSH20"):
            return b"", tail
        # البحث عن نهاية الكود: آخر RETURN/STOP/REVERT/SELFDESTRUCT
        for ins in ins_list:
            if ins.name in ("RETURN", "STOP", "REVERT", "SELFDESTRUCT", "INVALID"):
                code_end = ins.pc + 1
                if code_end < len(tail):
                    return tail[:code_end], tail[code_end:]
    except Exception:
        pass
    return b"", tail


# ---------------------------- جلب البيانات ----------------------------
def fetch_creation_bytecode(address: str, chain: str, etherscan_key: Optional[str]) -> Optional[bytes]:
    chain_id = ETHERSCAN_CHAIN_IDS.get(chain)
    if not chain_id or not etherscan_key:
        print("[!] تحذير: لم يتم توفير مفتاح Etherscan API", file=sys.stderr)
        return None
    url = (f"https://api.etherscan.io/v2/api?chainid={chain_id}"
           f"&module=contract&action=getcontractcreation"
           f"&contractaddresses={address}&apikey={etherscan_key}")
    try:
        data = requests.get(url, timeout=15).json()
    except Exception as e:
        print(f"[!] فشل طلب Etherscan: {e}", file=sys.stderr)
        return None
    if data.get("status") != "1" or not data.get("result"):
        print(f"[!] Etherscan لم يُرجع بيانات الإنشاء: {data.get('message')}", file=sys.stderr)
        return None
    tx_hash = data["result"][0]["txHash"]
    print(f"[*] معاملة الإنشاء: {tx_hash}")
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    try:
        return bytes(w3.eth.get_transaction(tx_hash)["input"])
    except Exception as e:
        print(f"[!] فشل جلب المعاملة: {e}", file=sys.stderr)
        return None


def fetch_runtime_bytecode(address: str, chain: str) -> bytes:
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    try:
        return bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
    except Exception as e:
        print(f"[!] فشل جلب runtime bytecode: {e}", file=sys.stderr)
        sys.exit(1)


def fetch_contract_abi(address: str, chain: str, etherscan_key: Optional[str]) -> Optional[List]:
    """جلب ABI للعقد المتحقق منه عبر Etherscan."""
    chain_id = ETHERSCAN_CHAIN_IDS.get(chain)
    if not chain_id or not etherscan_key:
        return None
    url = (f"https://api.etherscan.io/v2/api?chainid={chain_id}"
           f"&module=contract&action=getabi&address={address}&apikey={etherscan_key}")
    try:
        data = requests.get(url, timeout=15).json()
        if data.get("status") == "1" and data.get("result"):
            return json.loads(data["result"])
    except Exception:
        pass
    return None


def fetch_storage_slots(address: str, chain: str, num_slots: int = 10) -> List[Dict]:
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    results = []
    addr = Web3.to_checksum_address(address)
    for i in range(num_slots):
        try:
            val = bytes(w3.eth.get_storage_at(addr, i))
            if val != b"\x00" * 32:
                results.append({"slot": i, "hex": val.hex(), "entropy": round(shannon_entropy(val), 4)})
        except Exception:
            pass
    return results


# ---------------------------- التحليل ----------------------------
def extract_constructor_args(creation: bytes, runtime: bytes) -> Optional[bytes]:
    """استخراج الذيل بعد runtime داخل creation."""
    if len(creation) <= len(runtime):
        return None
    idx = creation.find(runtime)
    if idx > 0:
        return creation[idx + len(runtime):]
    runtime_no_cbor = strip_cbor_metadata(runtime)
    if runtime_no_cbor != runtime:
        idx = creation.find(runtime_no_cbor)
        if idx > 0:
            return creation[idx + len(runtime_no_cbor):]
    if creation[:len(runtime)] == runtime:
        return creation[len(runtime):]
    return None


def analyze_runtime(runtime: bytes, source: str = "runtime") -> List[Dict]:
    findings = []
    cleaned = strip_cbor_metadata(runtime)
    if len(cleaned) < len(runtime):
        print(f"[*] تمت إزالة {len(runtime) - len(cleaned)} بايت CBOR")
    try:
        instructions = list(disassemble_all(cleaned))
    except Exception as e:
        print(f"[!] فشل التفكيك: {e}", file=sys.stderr)
        return findings
    print(f"[*] تم تفكيك {len(instructions)} تعليمة")

    for ins in instructions:
        if not ins.name.startswith("PUSH"):
            continue
        data = _operand_to_bytes(ins)
        if not data:
            continue
        offset = ins.pc

        if is_printable_ascii(data):
            findings.append({"type": "string", "offset": hex(offset), "length": len(data),
                             "value": data.decode("ascii", errors="replace"), "source": source})

        if len(data) >= MIN_BLOB_LEN:
            h = shannon_entropy(data)
            if h >= ENTROPY_THRESHOLD:
                hex_str = data.hex()
                if hex_str not in KNOWN_CONSTANTS:
                    findings.append({"type": "high_entropy", "offset": hex(offset), "length": len(data),
                                     "entropy": round(h, 4), "hex_preview": hex_str[:32] + "...",
                                     "source": source})

        if len(data) == 32:
            hex_str = data.hex()
            if hex_str not in KNOWN_CONSTANTS and not any(
                f["type"] == "high_entropy" and f["offset"] == hex(offset) for f in findings
            ):
                findings.append({"type": "bytes32_constant", "offset": hex(offset), "length": 32,
                                 "entropy": round(shannon_entropy(data), 4), "hex": hex_str,
                                 "source": source})
    return findings


def analyze_constructor_data(args: bytes, abi: Optional[List]) -> List[Dict]:
    """تحليل بيانات الذيل مع محاولة فك تشفير ABI."""
    findings = []
    if not args:
        return findings

    # محاولة فك تشفير ABI
    decoded = None
    if abi:
        try:
            from eth_abi import decode as abi_decode
            # البحث عن constructor في ABI
            ctor = next((x for x in abi if x.get("type") == "constructor"), None)
            if ctor:
                input_types = [inp["type"] for inp in ctor.get("inputs", [])]
                decoded_values = abi_decode(input_types, args)
                decoded = {inp["name"] or f"arg{i}": str(val) for i, (inp, val) in enumerate(zip(ctor["inputs"], decoded_values))}
                findings.append({"type": "constructor_args_decoded", "decoded": decoded,
                                 "note": "تم فك التشفير باستخدام ABI"})
        except Exception as e:
            print(f"[*] فك تشفير ABI فشل: {e}")

    # تحليل خام
    findings.append({"type": "constructor_args_raw", "length": len(args),
                     "entropy": round(shannon_entropy(args), 4), "hex": args.hex()})

    for i in range(0, len(args), 32):
        chunk = args[i:i + 32]
        if len(chunk) >= MIN_STRING_LEN and is_printable_ascii(chunk):
            findings.append({"type": "constructor_arg_string", "offset": f"tail+{i}",
                             "value": chunk.decode("ascii", errors="replace")})
    return findings


def analyze_storage(slots: List[Dict]) -> List[Dict]:
    findings = []
    for s in slots:
        val = bytes.fromhex(s["hex"])
        is_address_like = val[:12] == b"\x00" * 12
        is_small_int = val.count(0) > 24
        if not is_address_like and not is_small_int:
            findings.append({"type": "storage_value", "slot": s["slot"], "hex": s["hex"],
                             "entropy": s["entropy"],
                             "note": "قيمة storage غير معتادة، قد تكون بيانات حساسة"})
    return findings


# ---------------------------- البرنامج الرئيسي ----------------------------
def main():
    parser = argparse.ArgumentParser(description="EVM Bytecode Forensics")
    parser.add_argument("address", help="عنوان العقد")
    parser.add_argument("--chain", default="ethereum", choices=list(RPC_ENDPOINTS.keys()))
    parser.add_argument("--etherscan-key", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-constructor", action="store_true")
    parser.add_argument("--check-storage", action="store_true")
    parser.add_argument("--storage-slots", type=int, default=10)
    args = parser.parse_args()

    print(f"[*] جلب runtime bytecode للعقد {args.address} على {args.chain}...")
    runtime = fetch_runtime_bytecode(args.address, args.chain)
    print(f"[*] طول runtime: {len(runtime)} بايت")
    if not runtime:
        print("[!] العقد لا يحتوي على كود")
        sys.exit(1)

    all_findings = []
    print("\n[*] تحليل runtime bytecode...")
    all_findings.extend(analyze_runtime(runtime))

    abi = fetch_contract_abi(args.address, args.chain, args.etherscan_key)
    if abi:
        print("[*] تم جلب ABI للعقد")

    if not args.no_constructor:
        print("\n[*] جلب creation bytecode...")
        creation = fetch_creation_bytecode(args.address, args.chain, args.etherscan_key)
        if creation:
            print(f"[*] طول creation: {len(creation)} بايت")
            tail = extract_constructor_args(creation, runtime)
            if tail:
                code_part, data_part = split_code_and_args(tail)
                if code_part:
                    print(f"[*] تم فصل {len(code_part)} بايت كود EVM، {len(data_part)} بايت بيانات")
                all_findings.extend(analyze_constructor_data(data_part, abi))

    if args.check_storage:
        print(f"\n[*] قراءة {args.storage_slots} storage slots...")
        slots = fetch_storage_slots(args.address, args.chain, args.storage_slots)
        print(f"[*] تم العثور على {len(slots)} slot غير صفري")
        all_findings.extend(analyze_storage(slots))

    print("\n" + "=" * 60)
    print("نتائج التحليل")
    print("=" * 60)
    if args.json:
        print(json.dumps(all_findings, indent=2, ensure_ascii=False))
    else:
        if not all_findings:
            print("لم يتم اكتشاف أي بيانات مشبوهة.")
        for f in all_findings:
            print(f"\n[{f['type'].upper()}]")
            for k, v in f.items():
                if k != "type":
                    print(f"  {k}: {v}")
    print("\n" + "-" * 60)
    print(f"إجمالي الاكتشافات: {len(all_findings)}")


if __name__ == "__main__":
    main()
