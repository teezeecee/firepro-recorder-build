#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_se_player_play_match_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_SE_PLAYER_PLAY_MATCH_SE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005277","0x00321504",374,"4c90d23ad41281c6f3411dd71c82635d6b56e0a15c80f80d2abf775639f9a4f9")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(134,26,10)
assert s["dll"]["entry"]["raw_seid_valid_range"]=={"min_inclusive":0,"max_inclusive":108}
assert s["dll"]["vibration"]["vib_time"]["raw_floor_when_nonpositive"]==10
assert s["dll"]["vibration"]["vib_time"]["raw_cap_when_not_less_than"]==60
assert s["dll"]["player_side_raw_branches"]["breath_ids"]==[31,32]
assert s["dll"]["player_side_raw_branches"]["out_of_ring_remap"]["input_ids"]==[7,8,9,10,11,12,13,14,58]
assert s["dll"]["player_side_raw_branches"]["out_of_ring_remap"]["replacement_raw_seid"]==48
assert s["dll"]["shared_tail"]["wait_list"]["zero_effect"]=="store raw 2"
assert s["dll"]["shared_tail"]["final_call"]["arguments"]==["seid","vol"]
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0058"
print("DLL MATCH SE PLAYER PLAY MATCH SE SUMMARY: PASS")
