#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"ring_shake_cage.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_RING_SHAKE_CAGE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600510A","0x0030E2F0","200001")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("tiny",8,"dc90ddc959a5183de014264fdbd38c6d4f4b92fa95ac83949817fbbe1adb79b3")
assert m["body_hex"]=="02167d6f6300042a"
assert s["dll"]["field"]["token"]=="0x0400636F"
assert s["dll"]["inbound_direct_reference"]["canonical_fact"]=="FACT-0015"
print("DLL RING SHAKE CAGE SUMMARY: PASS")
