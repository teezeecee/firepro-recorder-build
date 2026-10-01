#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"cheer_voice_one_shot.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_CHEER_VOICE_ONE_SHOT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052AC","0x00322D48",120,"a32030b069fd4cdecafcd55c677b9ffe0f3c2220729d455c31ae7796c31b4fb2")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(47,6,3)
assert s["dll"]["exact_gates"][2]["condition"]=="vid < 42"
assert s["dll"]["volume_flow"]["lower_gate"]["ordered_negative_effect"]=="local = 0.0f"
assert s["dll"]["volume_flow"]["upper_gate"]["ordered_greater_effect"]=="local = 1.0f"
assert s["dll"]["playback"]["raw_audio_src_info_index"]==6
assert s["dll"]["fact_0079_bridge"]["call_il"]=="0x00A5"
print("DLL CHEER VOICE ONE SHOT SUMMARY: PASS")
