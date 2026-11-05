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
# عناوين RPC العامة (يمكن استبدالها بعُقد خاصة)
RPC_ENDPOINTS = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "base": "https://mainnet.base.org",
}

# معرفات chainId لـ Etherscan API
ETHERSCAN_CHAIN_IDS = {
    "ethereum": 1,
    "bsc": 56,
    "arbitrum": 42161,
    "base": 8453,
}

# عتبة الإنتروبيا (بايت/بايت)
ENTROPY_THRESHOLD = 7.0
# الحد الأدنى لطول الكتلة عالية الإنتروبيا
MIN_BLOB_LEN = 16
# الحد الأدنى لطول السلسلة النصية
MIN_STRING_LEN = 8

# ---------------------------- أدوات مساعدة ----------------------------
def shannon_entropy(data: bytes) -> float:
    """حساب إنتروبيا شانون"""
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
    """التحقق مما إذا كانت البيانات سلسلة ASCII قابلة للطباعة"""
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
    عادةً ما تكون آخر بايتين هي طول بيانات CBOR الوصفية.
    """
    if len(bytecode) < 2:
        return bytecode
    # محاولة قراءة آخر بايتين كطول CBOR
    length = int.from_bytes(bytecode[-2:], "big")
    if 0 < length < len(bytecode) - 2:
        # التحقق من أن البداية تحتوي على بادئة CBOR الشائعة (a1/a2/a3...)
        start = len(bytecode) - 2 - length
        if start >= 0:
            prefix = bytecode[start:start + 1]
            if prefix and prefix[0] in (0xa1, 0xa2, 0xa3, 0xa4, 0xa5):
                return bytecode[:start]
    return bytecode


# ---------------------------- جلب البيانات ----------------------------
def fetch_creation_bytecode(address: str, chain: str, etherscan_key: Optional[str]) -> Optional[bytes]:
    """
    جلب creation bytecode.
    الأولوية: الحصول على txHash من Etherscan ثم الحصول على input من RPC.
    """
    chain_id = ETHERSCAN_CHAIN_IDS.get(chain)
    if not chain_id or not etherscan_key:
        print("[!] تحذير: لم يتم توفير مفتاح Etherscan API، لا يمكن جلب creation bytecode", file=sys.stderr)
        return None

    # 1. الحصول على txHash لإنشاء العقد
    url = f"https://api.etherscan.io/v2/api?chainid={chain_id}&module=contract&action=getcontractcreation&contractaddresses={address}&apikey={etherscan_key}"
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

    # 2. الحصول على input للمعاملة من RPC
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    try:
        tx = w3.eth.get_transaction(tx_hash)
        return bytes(tx["input"])
    except Exception as e:
        print(f"[!] فشل جلب المعاملة من RPC: {e}", file=sys.stderr)
        return None


def fetch_runtime_bytecode(address: str, chain: str) -> bytes:
    """جلب runtime bytecode"""
    w3 = Web3(Web3.HTTPProvider(RPC_ENDPOINTS[chain]))
    try:
        code = w3.eth.get_code(Web3.to_checksum_address(address))
        return bytes(code)
    except Exception as e:
        print(f"[!] فشل جلب runtime bytecode: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------- التحليل الأساسي ----------------------------
def extract_constructor_args(creation: bytes, runtime: bytes) -> Optional[bytes]:
    """
    استخراج معاملات المُنشئ بمقارنة اللاحقة.
    إذا كانت creation أطول من runtime، فإن الجزء الإضافي في النهاية هو معاملات المُنشئ.
    """
    if len(creation) <= len(runtime):
        return None
    # التحقق من أن runtime هي بادئة creation
    if creation[:len(runtime)] == runtime:
        args = creation[len(runtime):]
        print(f"[*] تم اكتشاف {len(args)} بايت من معاملات المُنشئ المحتملة")
        return args
    else:
        # قد تحتوي creation على بيانات وصفية، جرب البحث عن أطول بادئة مشتركة
        # إستراتيجية مبسطة: العثور على أطول بادئة مشتركة
        for i in range(min(len(creation), len(runtime)), 0, -1):
            if creation[:i] == runtime[:i]:
                args = creation[i:]
                if args:
                    print(f"[*] تم اكتشاف {len(args)} بايت من معاملات المُنشئ المحتملة (طريقة البادئة المشتركة)")
                    return args
                break
    return None


def analyze_runtime(runtime: bytes, source: str = "runtime"):
    """تحليل runtime bytecode: التفكيك، الإنتروبيا، السلاسل النصية"""
    findings = []
    # إزالة CBOR
    cleaned = strip_cbor_metadata(runtime)
    if len(cleaned) < len(runtime):
        print(f"[*] تمت إزالة {len(runtime) - len(cleaned)} بايت من بيانات CBOR الوصفية")

    # التفكيك
    try:
        instructions = list(disassemble_all(cleaned))
    except Exception as e:
        print(f"[!] فشل التفكيك: {e}", file=sys.stderr)
        return findings

    print(f"[*] تم تفكيك {len(instructions)} تعليمة")

    for ins in instructions:
        if ins.name.startswith("PUSH"):
            data = ins.operand
            if not data:
                continue
            offset = ins.pc

            # 1. اكتشاف السلاسل النصية
            if is_printable_ascii(data):
                findings.append({
                    "type": "string",
                    "offset": hex(offset),
                    "length": len(data),
                    "value": data.decode("ascii", errors="replace"),
                    "source": source,
                    "instruction": ins.name,
                })

            # 2. اكتشاف الإنتروبيا العالية
            if len(data) >= MIN_BLOB_LEN:
                h = shannon_entropy(data)
                if h >= ENTROPY_THRESHOLD:
                    findings.append({
                        "type": "high_entropy",
                        "offset": hex(offset),
                        "length": len(data),
                        "entropy": round(h, 4),
                        "hex_preview": data[:16].hex() + "..." if len(data) > 16 else data.hex(),
                        "source": source,
                        "instruction": ins.name,
                    })

    return findings


def analyze_constructor_args(args: bytes):
    """تحليل معاملات المُنشئ (البحث عن سلاسل نصية وكتل عالية الإنتروبيا)"""
    findings = []
    if not args:
        return findings

    # فحص الإنتروبيا الكلية
    h_total = shannon_entropy(args)
    findings.append({
        "type": "constructor_args_raw",
        "offset": "tail",
        "length": len(args),
        "entropy": round(h_total, 4),
        "hex": args.hex(),
    })

    # تقسيم إلى كتل 32 بايت للفحص
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
        # اكتشاف السلاسل النصية
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
        description="EVM Bytecode Forensics - تحليل العقود المنشورة، واستخراج معاملات المُنشئ والبيانات المشبوهة"
    )
    parser.add_argument("address", help="عنوان العقد")
    parser.add_argument("--chain", default="ethereum", choices=list(RPC_ENDPOINTS.keys()), help="السلسلة (افتراضي: ethereum)")
    parser.add_argument("--etherscan-key", help="مفتاح Etherscan API (مطلوب لجلب creation bytecode)", default=None)
    parser.add_argument("--json", action="store_true", help="إخراج JSON")
    parser.add_argument("--no-constructor", action="store_true", help="تخطي تحليل معاملات المُنشئ (عندما لا يتوفر مفتاح API)")

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

    # 3. جلب creation bytecode وتحليل معاملات المُنشئ
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
                print("[*] لم يتم اكتشاف معاملات مُنشئ إضافية (قد لا تكون هناك معاملات، أو فشلت المطابقة)")
        else:
            print("[!] تخطي تحليل معاملات المُنشئ (لا يمكن جلب creation bytecode)")

    # 4. الإخراج
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
        print("[!] تم اكتشاف معاملات مُنشئ محتملة، يُرجى التحقق يدويًا مما إذا كانت تحتوي على بيانات حساسة")
    if any(f["type"] == "high_entropy" for f in all_findings):
        print("[!] تم اكتشاف كتل عالية الإنتروبيا في runtime، يُرجى التحقق يدويًا")


if __name__ == "__main__":
    main()
