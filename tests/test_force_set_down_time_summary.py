#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"force_set_down_time.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_FORCE_SET_DOWN_TIME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06004F0C","0x002E6C9C",49,"f62c7b101e9f67f9c7e8d3aaa1de4964a53b2669013d4574f0b8ecb2e9bc732c")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(17,1,2)
assert s["dll"]["exact_body"][2]=="this.SetDownTime(0)"
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0049" and s["dll"]["caller_bridge"]["call_il"]=="0x02AD"
print("DLL FORCE SET DOWN TIME SUMMARY: PASS")
