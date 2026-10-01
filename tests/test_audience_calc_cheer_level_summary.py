#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audience_calc_cheer_level.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIENCE_CALC_CHEER_LEVEL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060047E0","0x0029018C",477,"ba5e6b908f65b9feecf9b3c43ab61fbb139abf93eea50f11ae66585a92efbc32")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(164,31,11)
assert s["dll"]["timed_refresh"]["condition"]=="(MatchMain.matchTime.sec + 1) % 20 == 0"
assert s["dll"]["timed_refresh"]["raw_player_indices"]=={"min_inclusive":0,"max_inclusive":7}
assert s["dll"]["zone_scan"]["raw_zone_values"]==[1,3,8,9]
assert s["dll"]["zone_scan"]["trigger_count"]==2
assert s["dll"]["final_clamp"]=={"field":"CheerLevel_Total","min":-4,"max":4}
assert s["dll"]["fact_0079_bridge"]["call_il"]=="0x0024"
print("DLL AUDIENCE CALC CHEER LEVEL SUMMARY: PASS")
