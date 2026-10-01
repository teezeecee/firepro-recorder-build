#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"calc_touch_time.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_CALC_TOUCH_TIME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06004FFE","0x002FC064",129,"47a7f7261543bcf1382b1f1095a756cf101300461f48a08ca1e06c7ac5288589")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(51,2,2)
assert s["dll"]["random_call"]["fact_id"]=="FACT-0032"
assert s["dll"]["random_call"]["min_expression"]=="-touchTimePrm_RandomRange"
assert s["dll"]["random_call"]["max_expression"]=="touchTimePrm_RandomRange + 1"
assert s["dll"]["exact_expression"]=="local5 = touchTimePrm_Base + Int32((100 - aiParam.touchCond) * touchTimePrm_Coefficient) + sampledRandom"
assert s["dll"]["output"]["raw_multiplier"]==30
assert s["dll"]["caller_bridges"][0]["fact_id"]=="FACT-0045"
print("DLL CALC TOUCH TIME SUMMARY: PASS")
