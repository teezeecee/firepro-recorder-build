#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"skill_data_standard_wrapper.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SKILL_DATA_STANDARD_WRAPPER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005264","0x0031FF20",14,"9db7aaaf1198a49f3fd4637000dab60fa02b6ede3a444f5dfb2a09e7e6e844f9")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(6,0,1)
assert s["dll"]["exact_wrapper"]["raw_offset"]==2675
assert s["dll"]["exact_wrapper"]["callee"]["token"]=="0x06005262"
assert s["dll"]["fact_0070_bridge"]["call_il"]=="0x0023"
print("DLL SKILL DATA STANDARD WRAPPER SUMMARY: PASS")
