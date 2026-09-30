#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"process_critical.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_PROCESS_CRITICAL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06004ECA","0x002E11B0","20010112a9a8",277,"95fcc98f9fe079ae95ecf2d72104145a28273b1030b2fc9db039abcfb330fd30")
assert m["parameters"]==[{"sequence":1,"name":"sd","type":"SkillData"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(82,11,6)
assert s["dll"]["entry_and_damage_record"]["raw_flag_mask"]==40
assert [x["skill_field"] for x in s["dll"]["power_zeroing"]]==["atkPow_HP","atkPow_SP","atkPow_Neck","atkPow_Arm","atkPow_Waist","atkPow_Leg","atkPow_BP"]
assert s["dll"]["flag_64_branch"]["raw_flag_mask"]==64
assert s["dll"]["flag_8_presentation"]["raw_flag_mask"]==8
assert s["dll"]["flag_8_presentation"]["true_path"]["arguments"]==[30,1.0,"this.PlIdx"]
assert s["dll"]["flag_8_presentation"]["false_path"]["arguments"]==[1]
assert s["dll"]["apply_damage_bridge"]["fact_id"]=="FACT-0020" and s["dll"]["apply_damage_bridge"]["call_il"]=="0x01D2"
print("DLL PROCESS CRITICAL SUMMARY: PASS")
