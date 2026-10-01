#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_voice_leaf.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_VOICE_LEAF_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052A9","0x00322C58",122,"6168083a2b8e7ff12b16c44ba759062f611c24ac73de637c5461485234e65b74")
assert m["parameters"]==[{"sequence":1,"name":"vid","type":"Int32"},{"sequence":2,"name":"volume","type":"Float32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(35,6,3)
assert s["dll"]["exact_gates"][2]["condition"]=="vid < 24"
assert s["dll"]["volume_flow"]["negative_gate"]["opcode"]=="bge.un"
assert s["dll"]["volume_flow"]["upper_gate"]["opcode"]=="ble.un"
assert s["dll"]["playback"]["raw_audio_src_info_index"]==4
assert s["dll"]["fact_0076_bridge"]["arguments"]==["vid",1.0]
print("DLL REFEREE VOICE LEAF SUMMARY: PASS")
