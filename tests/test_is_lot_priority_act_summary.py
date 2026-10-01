#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"is_lot_priority_act.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_IS_LOT_PRIORITY_ACT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005008","0x002FCE8C","200102118628",534,"95906f7bec4bf47c92137113114297c666b46a997ca3a1c487e0a1b71c496461")
assert m["parameters"]==[{"sequence":1,"name":"act","type":"AIPriorityActEnum"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(131,29,5)
sw=s["dll"]["switch"]
assert sw["count"]==41 and sw["default_effect"]=="branch to true"
assert [g["raw_acts"] for g in sw["groups"]]==[
 [0,1,2,3,4,5],[6,7],[8,9],[10,11,12,13],[14,15,16,17],[18,19,20],[21],
 [22,23,24,25,26,27,28,29,30,31,32,33,34],[35,36,37,38,39,40]]
c=s["dll"]["conditional_tokens"]
assert c["raw_state_values"]==[18,17] and c["raw_forbidden_ring_kinds"]==[1,3]
assert c["raw_act21_equipment_argument"]==47
assert s["dll"]["process_priority_act_bridge"]["call_il"]=="0x0155"
print("DLL IS LOT PRIORITY ACT SUMMARY: PASS")
