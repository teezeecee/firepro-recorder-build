#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_manager_play_match_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MANAGER_PLAY_MATCH_SE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052A8","0x00322B90",122,"56ce94a2d961f8cb774c95924d1cab7a28ed7dc521501dc72ace69c7ce39c162")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(45,6,3)
assert s["dll"]["gates"]["raw_sound_number_range"]=={"min_inclusive":0,"max_inclusive":108}
assert s["dll"]["volume_path"]["expression"]=="local0 = Volume_Se * volume"
assert s["dll"]["volume_path"]["lower_comparison"]["opcode"]=="bge.un"
assert s["dll"]["volume_path"]["upper_comparison"]["opcode"]=="ble.un"
assert s["dll"]["audio_dispatch"]["raw_index"]==2
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0060"
print("DLL MENU SOUND MANAGER PLAY MATCH SE SUMMARY: PASS")
