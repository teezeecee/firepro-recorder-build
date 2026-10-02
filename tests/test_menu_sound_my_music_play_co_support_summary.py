#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_play_co_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_PLAY_CO_SUPPORT_V1"
assert s["dll"]["owner_type"]["token"]=="0x02000F73"
m=s["dll"]["methods"]
assert [x["token"] for x in m]==["0x06007510","0x06007511","0x06007512","0x06007513"]
assert [x["rva"] for x in m]==["0x00325600","0x00325608","0x00325610","0x00325620"]
assert m[0]["code_sha256"]==m[1]["code_sha256"]=="b8e8332bb9870be9197c321e9365333a1cc8b38ee55cb82ca1e204f0d455de8b"
assert (m[2]["code_size"],m[2]["code_sha256"])==(15,"02a2aa96e1a791fff16cf503f1e698d0ecfbf56270e49599e8042faf50fd0a18")
assert (m[3]["code_size"],m[3]["code_sha256"])==(6,"feef1163dc69f21cc1201b1ec63d1a60afc2af2ce98036d760713f22a2968a49")
assert s["dll"]["fields"]["current"]["token"]=="0x0400C26D"
assert s["dll"]["fields"]["disposing"]["token"]=="0x0400C26E"
assert s["dll"]["fields"]["pc"]["token"]=="0x0400C26F"
assert s["dll"]["reset_constructor"]["token"]=="0x0A0000EE"
assert s["dll"]["relationship_status"]=="SAME_GENERATED_TYPE_SUPPORT_METHODS_NOT_RUNTIME_CALL_EDGES"
print("DLL MENU SOUND MY MUSIC PLAY CO SUPPORT SUMMARY: PASS")
