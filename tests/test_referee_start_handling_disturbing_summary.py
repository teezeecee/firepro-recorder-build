#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_start_handling_disturbing.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_START_HANDLING_DISTURBING_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600509D","0x00308528",202,"2b83b8d57051b7b88b861140401b12d2ec72246595a3021b601c6cc10754b96c")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(68,3,9)
assert s["dll"]["referee_flow"]["state_write"]["raw_value"]==18
assert s["dll"]["referee_flow"]["animation_selection"]["default_raw_id"]==1158
assert s["dll"]["referee_flow"]["animation_selection"]["replacement_raw_id"]==1159
assert s["dll"]["referee_flow"]["animation_selection"]["replacement_when_post_reverse_pl_dir_in"]==[1,5]
assert s["dll"]["target_player_flow"]["req_basic_anm"]["arguments"]==["animator.BasicSkillID",False,-1]
assert s["dll"]["target_player_flow"]["start_anm"]["arguments"]==[1]
assert s["dll"]["voice_flow"]["random_call"]["arguments"]==[0,3]
assert s["dll"]["fact_0085_bridge"]["call_il"]=="0x0216"
print("DLL REFEREE START HANDLING DISTURBING SUMMARY: PASS")
