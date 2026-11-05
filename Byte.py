#!/usr/bin/env python3
"""
EVM Bytecode Forensics CLI
تحليل بيانات العقود المنشورة على Ethereum/BSC/Arbitrum/Base،
واستخراج معاملات المُنشئ، والأجزاء عالية الإنتروبيا، والسلاسل النصية المحتملة الحساسة،
مع خيار قراءة storage slots للكشف عن المتغيرات الخاصة.
"""

import argparse
import json
import math
import sys
from collections import Counter
from typing import Optional

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

# قائمة بيضاء موسعة لأحداث ERC20/ERC721 الشائعة (topic0)
KNOWN_CONSTANTS = {
    # keccak256("Transfer(address,address,uint256)")
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    # keccak256("Approval(address,address,uint256)")
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
    # keccak256("ApprovalForAll(address,address,bool)")
    "17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31",
    # keccak256("Transfer(address,address,uint256)") - ERC721
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    # keccak256("OwnershipTransferred(address,address)")
    "8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
    # keccak256("Deposit(address,uint256)")
    "e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c",
    # keccak256("Withdrawal(address,uint256)")
    "7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65",
    # keccak256("Swap(address,uint256,uint256,uint256,uint256,address)")
    "d78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
    # keccak256("Sync(uint112,uint112)")
    "1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1",
}

# EIP-1967 implementation slot (proxy)
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"


# ---------------------------- أدوات مساعدة ----------------------------
def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_printable_ascii(data: bytes) -> bool:
    if not isinstance(data, (bytes, bytearray)):
        return False
    if len(data) < MIN_STRING_LEN:
        return False
    try:
        text = data.decode("ascii")
        return all(32 <= ord(c) < 127 for c in text)
    except UnicodeDecodeError:
        return False


def strip_cbor_metadata(bytecode: bytes) -> bytes:
    """
    إزالة بيانات CBOR الوصفية في نهاية Solidity.
    آخر بايتين = طول CBOR (big-endian)، والبادئة تبدأ بـ 0xa1/0xa2/0xa3
    """
    if len(bytecode) < 5:
        return bytecode
    length = int.from_bytes(bytecode[-2:], "big")
    if length == 0 or length + 2 > len(bytecode):
        return bytecode
    start = len(bytecode) - 2 - length
    if start < 0:
        return bytecode
    prefix = bytecode[start]
    if prefix in (0xa1, 0xa2, 0xa3):
        return bytecode[:start]
    return bytecode


def _operand_to_bytes(ins) -> Optional[bytes]:
    """تحويل operand الخاص بتعليمة PUSH إلى bytes بأمان (int/bytes/None)."""
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
        if size == 0:
            return None
        return op.to_bytes(size, byteorder="big")
    return None


# ---------------------------- جلب البيانات ----------------------------
def fetch_creation_bytecode(address: str, chain: str, etherscan_key: Optional[str]) -> Optional[bytes]:
    chain_id = ETHERSCAN_CHAIN_IDS.get(chain)
    if not chain_id or not etherscan_key:
        print("[!] تحذير: لم يتم توفير مفتاح Etherscan API", file=sys.stderr)
        return None

    url = (
        f"https://api.etherscan.io/v2/api?chainid={chain_id}"
        f"&module=contract&action=getcontractcreation"
        f"&contractaddresses={address}&apikey={etherscan_key}"
    )
    try:
        resp = requests.get(url, timeout=15)
        data = resp.json()
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
        tx = w3.eth.get_transaction(tx_hash)
        return bytes(tx["input"])
    except Exception as e:
        print(f"[!] فشل جلب المعاملة من RPC: {e}", file=sys.stderr)
        return None


def fetch_runtime_bytecode(address: str, chain: str) -> bytes:
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(address))
        return bytes(code)
    except Exception as e:
        print(f"[!] فشل جلب runtime bytecode: {e}", file=sys.stderr)
        sys.exit(1)


def fetch_storage_slots(address: str, chain: str, num_slots: int = 10) -> list:
    """
    قراءة أول N slot من storage العقد.
    slots غير الصفرية تُعاد كقائمة من dicts.
    """
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    results = []
    checksum_addr = Web3.to_checksum_address(address)
    for i in range(num_slots):
        try:
            val = w3.eth.get_storage_at(checksum_addr, i)
            # web3.py يُرجع HexBytes؛ تحويل إلى bytes
            val_bytes = bytes(val)
            if val_bytes != b"\x00" * 32:
                results.append({
                    "slot": i,
                    "hex": val_bytes.hex(),
                    "entropy": round(shannon_entropy(val_bytes), 4),
                })
        except Exception as e:
            print(f"[!] فشل قراءة slot {i}: {e}", file=sys.stderr)
    return results


# ---------------------------- التحليل الأساسي ----------------------------
def extract_constructor_args(creation: bytes, runtime: bytes) -> Optional[bytes]:
    """
    استخراج معاملات المُنشئ بالبحث عن runtime داخل creation.
    ما بعد runtime = معاملات المُنشئ (إن وُجدت).
    """
    if len(creation) <= len(runtime):
        return None

    # المحاولة 1: البحث المباشر عن runtime داخل creation
    idx = creation.find(runtime)
    if idx > 0:
        after = creation[idx + len(runtime):]
        if after:
            print(f"[*] تم العثور على runtime داخل creation في offset {hex(idx)}")
            print(f"[*] تم اكتشاف {len(after)} بايت من معاملات المُنشئ المحتملة")
            return after

    # المحاولة 2: إزالة CBOR من runtime ثم البحث
    runtime_no_cbor = strip_cbor_metadata(runtime)
    if runtime_no_cbor != runtime:
        idx = creation.find(runtime_no_cbor)
        if idx > 0:
            after = creation[idx + len(runtime_no_cbor):]
            if after:
                print(f"[*] تم العثور على runtime (بعد إزالة CBOR) داخل creation في offset {hex(idx)}")
                print(f"[*] تم اكتشاف {len(after)} بايت من معاملات المُنشئ المحتملة")
                return after

    # المحاولة 3: مقارنة البادئة (الطريقة القديمة كاحتياط)
    if creation[:len(runtime)] == runtime:
        args = creation[len(runtime):]
        if args:
            print(f"[*] تم اكتشاف {len(args)} بايت (طريقة البادئة)")
            return args

    return None


def analyze_runtime(runtime: bytes, source: str = "runtime"):
    findings = []
    cleaned = strip_cbor_metadata(runtime)
    if len(cleaned) < len(runtime):
        print(f"[*] تمت إزالة {len(runtime) - len(cleaned)} بايت من بيانات CBOR الوصفية")

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
        if data is None:
            continue
        if not isinstance(data, (bytes, bytearray)):
            continue
        data = bytes(data)

        offset = ins.pc

        # 1. السلاسل النصية
        if is_printable_ascii(data):
            findings.append({
                "type": "string",
                "offset": hex(offset),
                "length": len(data),
                "value": data.decode("ascii", errors="replace"),
                "source": source,
                "instruction": ins.name,
            })

        # 2. الكتل عالية الإنتروبيا
        if len(data) >= MIN_BLOB_LEN:
            h = shannon_entropy(data)
            if h >= ENTROPY_THRESHOLD:
                hex_str = data.hex()
                if hex_str not in KNOWN_CONSTANTS and not hex_str.startswith("ddf252ad"):
                    findings.append({
                        "type": "high_entropy",
                        "offset": hex(offset),
                        "length": len(data),
                        "entropy": round(h, 4),
                        "hex_preview": data[:16].hex() + "..." if len(data) > 16 else hex_str,
                        "source": source,
                        "instruction": ins.name,
                    })

        # 3. ثوابت 32 بايت (حتى لو كانت إنتروبيا أقل من العتبة)
        if len(data) == 32:
            hex_str = data.hex()
            if hex_str not in KNOWN_CONSTANTS and not hex_str.startswith("ddf252ad"):
                # فقط إذا لم تكن قد أُضيفت بالفعل كـ high_entropy
                if not any(
                    f["type"] == "high_entropy" and f["offset"] == hex(offset)
                    for f in findings
                ):
                    h = shannon_entropy(data)
                    findings.append({
                        "type": "bytes32_constant",
                        "offset": hex(offset),
                        "length": 32,
                        "entropy": round(h, 4),
                        "hex": hex_str,
                        "source": source,
                        "instruction": ins.name,
                    })

    return findings


def analyze_constructor_args(args: bytes):
    findings = []
    if not args:
        return findings

    h_total = shannon_entropy(args)
    findings.append({
        "type": "constructor_args_raw",
        "offset": "tail",
        "length": len(args),
        "entropy": round(h_total, 4),
        "hex": args.hex(),
    })

    for i in range(0, len(args), 32):
        chunk = args[i:i + 32]
        if len(chunk) < 8:
            continue
        h = shannon_entropy(chunk)
        if h >= ENTROPY_THRESHOLD:
            findings.append({
                "type": "constructor_arg_high_entropy",
                "offset": f"tail+{i}",
                "length": len(chunk),
                "entropy": round(h, 4),
                "hex_preview": chunk[:16].hex() + "...",
            })
        if is_printable_ascii(chunk):
            findings.append({
                "type": "constructor_arg_string",
                "offset": f"tail+{i}",
                "length": len(chunk),
                "value": chunk.decode("ascii", errors="replace"),
            })

    return findings


def analyze_storage(slots: list):
    """تحليل storage slots: البحث عن قيم عالية الإنتروبيا أو ثوابت 32 بايت."""
    findings = []
    for s in slots:
        val_hex = s["hex"]
        val_bytes = bytes.fromhex(val_hex)
        # تجاهل القيم الصغيرة جداً (مثل uint صغيرة)
        if val_bytes == b"\x00" * 32:
            continue
        # إذا كانت القيمة تبدو كعنوان (12 بايت صفر + 20 بايت)
        is_address_like = val_bytes[:12] == b"\x00" * 12
        # إذا كانت القيمة تبدو كـ uint صغير (معظم البايتات صفر)
        zero_bytes = val_bytes.count(0)
        is_small_int = zero_bytes > 24

        if not is_address_like and not is_small_int:
            findings.append({
                "type": "storage_value",
                "slot": s["slot"],
                "hex": val_hex,
                "entropy": s["entropy"],
                "is_address_like": is_address_like,
                "note": "قيمة storage غير معتادة، قد تكون بيانات حساسة أو ثابت",
            })
    return findings


# ---------------------------- البرنامج الرئيسي ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Forensics - تحليل العقود المنشورة، واستخراج معاملات المُنشئ والبيانات المشبوهة"
    )
    parser.add_argument("address", help="عنوان العقد")
    parser.add_argument("--chain", default="ethereum", choices=list(RPC_ENDPOINTS.keys()))
    parser.add_argument("--etherscan-key", help="مفتاح Etherscan API", default=None)
    parser.add_argument("--json", action="store_true", help="إخراج JSON")
    parser.add_argument("--no-constructor", action="store_true", help="تخطي تحليل معاملات المُنشئ")
    parser.add_argument("--check-storage", action="store_true", help="قراءة أول 10 storage slots")
    parser.add_argument("--storage-slots", type=int, default=10, help="عدد slots للقراءة (افتراضي: 10)")

    args = parser.parse_args()

    # 1. جلب runtime
    print(f"[*] جلب runtime bytecode للعقد {args.address} على {args.chain}...")
    runtime = fetch_runtime_bytecode(args.address, args.chain)
    print(f"[*] طول runtime: {len(runtime)} بايت")

    if len(runtime) == 0:
        print("[!] العقد لا يحتوي على كود (ربما EOA أو عنوان خاطئ)")
        sys.exit(1)

    all_findings = []

    # 2. تحليل runtime
    print("\n[*] تحليل runtime bytecode...")
    runtime_findings = analyze_runtime(runtime, source="runtime")
    all_findings.extend(runtime_findings)

    # 3. تحليل creation bytecode
    if not args.no_constructor:
        print("\n[*] محاولة جلب creation bytecode...")
        creation = fetch_creation_bytecode(args.address, args.chain, args.etherscan_key)
        if creation:
            print(f"[*] طول creation bytecode: {len(creation)} بايت")
            constructor_args = extract_constructor_args(creation, runtime)
            if constructor_args:
                args_findings = analyze_constructor_args(constructor_args)
                all_findings.extend(args_findings)
            else:
                print("[*] لم يتم اكتشاف معاملات مُنشئ إضافية")
        else:
            print("[!] تخطي تحليل معاملات المُنشئ")

    # 4. تحليل storage (اختياري)
    if args.check_storage:
        print(f"\n[*] قراءة {args.storage_slots} storage slots...")
        slots = fetch_storage_slots(args.address, args.chain, args.storage_slots)
        print(f"[*] تم العثور على {len(slots)} slot غير صفري")
        storage_findings = analyze_storage(slots)
        all_findings.extend(storage_findings)

    # 5. الإخراج
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
                if k == "type":
                    continue
                print(f"  {k}: {v}")

    # ملخص
    print("\n" + "-" * 60)
    print(f"إجمالي الاكتشافات: {len(all_findings)}")
    if any(f["type"] == "constructor_args_raw" for f in all_findings):
        print("[!] تم اكتشاف معاملات مُنشئ محتملة، يُرجى التحقق يدويًا")
    if any(f["type"] == "high_entropy" or f["type"] == "bytes32_constant" for f in all_findings):
        print("[!] تم اكتشاف ثوابت/كتل في runtime، يُرجى التحقق يدويًا")
    if any(f["type"] == "storage_value" for f in all_findings):
        print("[!] تم اكتشاف قيم storage غير معتادة، يُرجى التحقق يدويًا")


if __name__ == "__main__":
    main()
