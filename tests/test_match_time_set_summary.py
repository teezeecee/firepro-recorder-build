#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_time_set.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_TIME_SET_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004905","0x002A7AF0",37,"94a90dfec6b4dda72ec1c11c69106555c2e093589c42bf30bfa37c5351f613d5")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(13,0,0)
assert [x["source"] for x in s["dll"]["exact_copies"]]==["t.min","t.sec","t.frm"]
assert s["dll"]["fact_0097_bridge"]["call_il"]=="0x00E2"
print("DLL MATCH TIME SET SUMMARY: PASS")
