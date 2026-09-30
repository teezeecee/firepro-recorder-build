#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"reset_checked_pri_act.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_RESET_CHECKED_PRI_ACT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06005007","0x002FCE60",29,"875a2b35635251f80de9831dffb13bc94a030a2edd52a8b96e0496d68a46e9ff")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(16,2,0)
assert s["dll"]["field"]=={"name":"checkedPriAct","token":"0x04006152"}
assert s["dll"]["exact_loop"]["condition"]=="index < 41"
assert s["dll"]["exact_loop"]["raw_cleared_index_range"]=={"min_inclusive":0,"max_inclusive":40}
assert s["dll"]["caller_bridge"]["call_il"]=="0x0014"
print("DLL RESET CHECKED PRI ACT SUMMARY: PASS")
