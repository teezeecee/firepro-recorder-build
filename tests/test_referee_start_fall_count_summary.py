#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_start_fall_count.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_START_FALL_COUNT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600509A","0x003081C4",258,"3688c9d5342ef0785ee92923ceb8862dc82d0e50d0aaa26e580f3487c9502f4b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(83,4,11)
assert s["dll"]["rope_path"]["collision_float_bits"]=="0x3F2AAAB0"
assert s["dll"]["rope_path"]["true_effects"][2]=="State = 23"
assert s["dll"]["normal_path"]["state_raw"]==9
assert s["dll"]["normal_path"]["request_expression"]=="AnmIDTbl_FallCount[MatchData.AnmOfsTbl_2Dir[PlDir]]"
assert s["dll"]["fact_0085_bridge"]["call_il"]=="0x005B"
print("DLL REFEREE START FALL COUNT SUMMARY: PASS")
