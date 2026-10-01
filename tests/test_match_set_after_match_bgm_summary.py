#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_set_after_match_bgm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_SET_AFTER_MATCH_BGM_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004924","0x002A95D8",195,"57fe61387e5df262b4c752819960c309b4a48a1a2299a231f8f5199a6e69eeb3")
assert m["parameters"]==[{"sequence":1,"name":"pl_idx","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(61,7,5)
assert s["dll"]["data_selection"]["edit_threshold"]["raw_value"]==10000
assert s["dll"]["data_selection"]["story_sentinel"]["raw_value"]==-2
assert s["dll"]["filename_flow"]["check_true"][0]["value"]==-2
assert s["dll"]["filename_flow"]["check_false"][0]["value"]==0
assert s["dll"]["fact_0093_bridge"]["call_il"]=="0x0062"
print("DLL MATCH SET AFTER MATCH BGM SUMMARY: PASS")
