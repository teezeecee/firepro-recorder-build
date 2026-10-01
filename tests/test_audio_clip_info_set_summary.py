#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audio_clip_info_set.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIO_CLIP_INFO_SET_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052C2","0x003237F5","2001011249")
assert (m["code_size"],m["code_sha256"])==(8,"5c1fa2fbc6a929b6fffb5ebb0e04fae4d1fa8b86b4d1984529906b46d8824dd0")
assert m["parameters"]==[{"sequence":1,"name":"clip","type":"UnityEngine.AudioClip"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,0)
assert s["dll"]["field"]["token"]=="0x0400874B"
assert [x["call_il"] for x in s["dll"]["fact_0111_bridges"]]==["0x00FF","0x0142","0x0172"]
assert all(x["array_index"]==33 for x in s["dll"]["fact_0111_bridges"])
print("DLL AUDIO CLIP INFO SET SUMMARY: PASS")
