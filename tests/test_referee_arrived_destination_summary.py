#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_arrived_destination.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_ARRIVED_DESTINATION_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600509F","0x00308668",545,"ec45a72452fcbddd71df0a05d3c7b9a68df75fa36c1452a36638468a5e9db5e4")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(169,14,15)
assert s["dll"]["switch"]["raw_case_range"]=={"min_inclusive":9,"max_inclusive":18}
assert s["dll"]["switch"]["targets"]=={"9":"0x005A","10":"0x0199","11":"0x00D6","12":"0x0070","13":"0x0115","14":"0x0070","15":"0x0065","16":"0x0154","17":"0x01DB","18":"0x0215"}
assert s["dll"]["exact_cases"]["9"]==["call Start_FallCount 0x0600509A"]
assert s["dll"]["exact_cases"]["15"]==["call Start_SubmissionCheck 0x0600509B"]
assert s["dll"]["exact_cases"]["18"]==["call Start_HandlingDisturbing 0x0600509D"]
assert s["dll"]["exact_cases"]["10"][-1]=="FrameWait=50"
assert s["dll"]["fact_0084_bridge"]["call_il"]=="0x0053"
print("DLL REFEREE ARRIVED DESTINATION SUMMARY: PASS")
