#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_decide_dir.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_DECIDE_DIR_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600508C","0x00307384",107,"619774a8896b2e0f017a07bcca09e6a9a2c976f75c90f2f8d648669cfb7172a1")
assert m["parameters"]==[{"sequence":1,"name":"pl_idx","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(36,4,4)
assert s["dll"]["lookup"]["missing_player_return"]==1
assert [x["opcode"] for x in s["dll"]["exact_branch_graph"]]==["bgt.un","bgt.un","bgt.un"]
assert s["dll"]["raw_return_set"]==[1,2,4,5]
assert s["dll"]["fact_0085_bridge"]["call_ils"]==["0x0095","0x016F","0x01A9","0x01EB"]
print("DLL REFEREE DECIDE DIR SUMMARY: PASS")
