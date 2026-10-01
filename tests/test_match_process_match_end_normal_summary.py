#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_process_match_end_normal.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_PROCESS_MATCH_END_NORMAL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004928","0x002A9904",261,"f204671841365e78a2dfef78bb7a34a0c483ee30ac13d388b9b28b22cd5f17e9")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(88,13,5)
assert s["dll"]["winner_controller_gate"]["raw_value"]==2
assert s["dll"]["winner_controller_gate"]["on_equal"]["raw_value"]==900
assert s["dll"]["loop"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":7}
assert [x["write_raw_result_position"] for x in s["dll"]["loop"]["non_winner_branches"]]==[1,2,3]
assert s["dll"]["final_writes"][0]["raw_value"]==1
assert s["dll"]["fact_0093_bridge"]["call_il"]=="0x0096"
print("DLL MATCH PROCESS MATCH END NORMAL SUMMARY: PASS")
