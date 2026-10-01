#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_check_file.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_CHECK_FILE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052B7","0x00323103","2001020e")
assert (m["code_size"],m["code_sha256"])==(43,"662652aabb116c9ffa4f8e994a1ad55ed75cb54c40114569e6a0b8be4c140978")
assert m["parameters"]==[{"sequence":1,"name":"fname","type":"String"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(15,2,3)
assert s["dll"]["field"]["token"]=="0x04003903"
assert s["dll"]["calls"]["file_exists"]["token"]=="0x0A000216"
assert [x["call_il"] for x in s["dll"]["fact_0133_bridges"]]==["0x0026","0x0065","0x011C"]
print("DLL MENU SOUND MY MUSIC CHECK FILE SUMMARY: PASS")
