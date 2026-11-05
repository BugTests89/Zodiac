#!/usr/bin/env python3
"""
EVM Bytecode Forensics CLI
تحليل بيانات العقود المنشورة على Ethereum/BSC/Arbitrum/Base،
واستخراج معاملات المُنشئ، والأجزاء عالية الإنتروبيا، والسلاسل النصية المحتملة الحساسة.
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

KNOWN_CONSTANTS = {
    "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
}


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
    # حماية صريحة ضد الأنواع غير المتوقعة
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
    if len(bytecode) < 2:
        return bytecode
    length = int.from_bytes(bytecode[-2:], "big")
    if 0 < length < len(bytecode) - 2:
        start = len(bytecode) - 2 - length
        if start >= 0:
            prefix = bytecode[start:start + 1]
            if prefix and prefix[0] in (0xa1, 0xa2, 0xa3, 0xa4, 0xa5):
                return bytecode[:start]
    return bytecode


def _operand_to_bytes(ins) -> Optional[bytes]:
    """
    تحويل operand الخاص بتعليمة PUSH إلى bytes بأمان.
    pyevmasm قد يُرجع int (مثل PUSH0) أو bytes أو None.
    """
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


# ---------------------------- التحليل الأساسي ----------------------------
def extract_constructor_args(creation: bytes, runtime: bytes) -> Optional[bytes]:
    if len(creation) <= len(runtime):
        return None
    if creation[:len(runtime)] == runtime:
        args = creation[len(runtime):]
        print(f"[*] تم اكتشاف {len(args)} بايت من معاملات المُنشئ المحتملة")
        return args

    runtime_no_cbor = strip_cbor_metadata(runtime)
    if creation[:len(runtime_no_cbor)] == runtime_no_cbor:
        args = creation[len(runtime_no_cbor):]
        if args:
            print(f"[*] تم اكتشاف {len(args)} بايت من معاملات المُنشئ (بعد إزالة CBOR)")
            return args

    for i in range(min(len(creation), len(runtime)), 0, -1):
        if creation[:i] == runtime[:i]:
            args = creation[i:]
            if args:
                print(f"[*] تم اكتشاف {len(args)} بايت من معاملات المُنشئ (بادئة مشتركة)")
                return args
            break
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

        # استخدام الدالة الآمنة التي تُرجع bytes أو None
        data = _operand_to_bytes(ins)
        if data is None:
            continue
        if not isinstance(data, (bytes, bytearray)):
            continue
        data = bytes(data)

        offset = ins.pc

        if is_printable_ascii(data):
            findings.append({
                "type": "string",
                "offset": hex(offset),
                "length": len(data),
                "value": data.decode("ascii", errors="replace"),
                "source": source,
                "instruction": ins.name,
            })

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


# ---------------------------- البرنامج الرئيسي ----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="EVM Bytecode Forensics - تحليل العقود المنشورة"
    )
    parser.add_argument("address", help="عنوان العقد")
    parser.add_argument("--chain", default="ethereum", choices=list(RPC_ENDPOINTS.keys()))
    parser.add_argument("--etherscan-key", help="مفتاح Etherscan API", default=None)
    parser.add_argument("--json", action="store_true", help="إخراج JSON")
    parser.add_argument("--no-constructor", action="store_true", help="تخطي تحليل معاملات المُنشئ")

    args = parser.parse_args()

    print(f"[*] جلب runtime bytecode للعقد {args.address} على {args.chain}...")
    runtime = fetch_runtime_bytecode(args.address, args.chain)
    print(f"[*] طول runtime: {len(runtime)} بايت")

    if len(runtime) == 0:
        print("[!] العقد لا يحتوي على كود")
        sys.exit(1)

    all_findings = []

    print("\n[*] تحليل runtime bytecode...")
    runtime_findings = analyze_runtime(runtime, source="runtime")
    all_findings.extend(runtime_findings)

    if not args.no_constructor:
        print("\n[*] محاولة جلب creation bytecode...")
        creation = fetch_creation_bytecode(args.address, args.chain, args.etherscan_key)
        if creation:
            print(f"[*] طول creation bytecode: {len(creation)} بايت")
            constructor_args = extract_constructor_args(creation, runtime)
            if constructor_args:
                all_findings.extend(analyze_constructor_args(constructor_args))
            else:
                print("[*] لم يتم اكتشاف معاملات مُنشئ إضافية")
        else:
            print("[!] تخطي تحليل معاملات المُنشئ")

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

    print("\n" + "-" * 60)
    print(f"إجمالي الاكتشافات: {len(all_findings)}")


if __name__ == "__main__":
    main()
