#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"try_to_do_priority_act.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_TRY_TO_DO_PRIORITY_ACT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005009","0x002FD0B0","200108118628",606,"f1818f56bcb7b04635a7c1b9cb814f1e20480577a20287b2d8ee4d438e109191")
assert m["parameters"]==[{"sequence":1,"name":"act","type":"AIPriorityActEnum"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(169,16,13)
sw=s["dll"]["switch"]
assert sw["count"]==41 and sw["default_effect"]=="branch to raw return 1"
assert [g["raw_acts"] for g in sw["groups"]]==[
 [0,1,2,3,4,5],[6,7],[8,9],[10,11,12,13],[14,15,16,17],[18,19,20],[21],
 [22,23,24,25,26,27,28,29,30,31,32,33,34],[35,36,37,38,39,40]]
c=s["dll"]["raw_constants"]
assert c["down_atk_duration"]==180 and c["performance_index_subtract"]==86 and c["run_attack_duration"]==768
assert c["act21_set_ai_act_raw_action"]==17 and c["grapple_arg2"]==2 and c["grapple_arg3"]==32
assert s["dll"]["process_priority_act_bridge"]["call_il"]=="0x0180"
print("DLL TRY TO DO PRIORITY ACT SUMMARY: PASS")
