#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_system_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_SYSTEM_SE_V1"
m=s["dll"]["load_system_se"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06005283","0x003219D0","000001")
assert (m["code_size"],m["code_sha256"])==(84,"a3013c457438736875e2b086380b1531557597d34461483561823549e742c67b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(31,4,3)
assert m["fields"]["system_se_file_list"]["token"]=="0x040086E8"
assert m["fields"]["audio_clip_info"]["token"]=="0x040086F4"
assert m["fields"]["audio_clip"]["token"]=="0x0400874B"
assert m["direct_calls"]["audio_clip_info_set"]=={"token":"0x060052C2","name":"AudioClipInfo.Set","call_il":"0x003D"}
a=s["dll"]["audio_clip_info_set"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x060052C2","0x003237F5",8,"5c1fa2fbc6a929b6fffb5ebb0e04fae4d1fa8b86b4d1984529906b46d8824dd0")
assert [x["call_il"] for x in s["dll"]["fact_0160_bridges"]]==["0x0097","0x00E6"]
print("DLL MENU SOUND LOAD SYSTEM SE SUMMARY: PASS")
