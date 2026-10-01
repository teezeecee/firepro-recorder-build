#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_play_bgm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_PLAY_BGM_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600529E","0x00322750","00020111aa2411aa18")
assert (m["code_size"],m["code_sha256"])==(309,"b8e1c3d745fe8e77062c61c6ed822cf58159f4de99e69e662c91b9646745eb2f")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(3,"0x1100120A","070212aa2c1280b9")
assert m["parameters"]==[{"sequence":1,"name":"bgm_type","type":"SYSTEM_SOUND"},{"sequence":2,"name":"type","type":"PLAY_TYPE"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(93,16,15)
assert s["dll"]["calls"]["my_music_play"]["token"]=="0x060052B8"
assert s["dll"]["calls"]["set_volume"]["call_ils"]==["0x009B","0x00AB","0x00BB","0x00CB","0x00DF"]
assert [x["call_il"] for x in s["dll"]["canonical_bridges"]]==["0x0145","0x00B4","0x00E8"]
print("DLL MENU SOUND PLAY BGM SUMMARY: PASS")
