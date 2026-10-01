#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"octagon_inside_cross_line.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_RING_OCTAGON_INSIDE_CROSS_LINE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x060050FB","0x0030CF88",538,"342c92172a4c47371d07312bf9b8d7bec1b5d2cd2cbe9019255e8282ee26b59f")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(172,6,6)
assert s["dll"]["switch_targets"]==["0x0050","0x00B4","0x0117","0x017C"]
assert [x["pb2"] for x in s["dll"]["cases"]]==[2,3,4,5]
assert s["dll"]["cases"][0]["edge"]==[["x1","y2"],["x2","y1"]]
assert s["dll"]["cases"][3]["moving_offset"]==["+s","-s"]
assert s["dll"]["intersection_tail"]["callee_token"]=="0x06004A92"
assert s["dll"]["fact_0050_bridge"]["call_il"]=="0x0162"
print("DLL OCTAGON INSIDE CROSS LINE SUMMARY: PASS")
