#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_change_bgm_theme.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_CHANGE_BGM_THEME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06005296","0x00322268","0003011187480202")
assert (m["code_size"],m["code_sha256"])==(399,"2e0905ada32d6f97c3a3ac37f28bb0722b6084a109618070cf1dfc1ea1fb4733")
assert (m["max_stack"],m["local_signature_token"])==(5,"0x11001202")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(119,10,28)
assert s["dll"]["strings"]["dlc_prefix"]["value"]=="dlc_assets/theme_music/"
assert s["dll"]["strings"]["resource_prefix"]["value"]=="Sound/Bgm/"
assert s["dll"]["direct_method_calls"]["get_instance"]["call_ils"]==["0x0074","0x008E"]
assert s["dll"]["direct_method_calls"]["audio_clip_set"]["call_ils"]==["0x00FF","0x0142","0x0172"]
assert [x["call_il"] for x in s["dll"]["fact_0108_bridges"]]==["0x003E","0x00B8","0x00EE"]
print("DLL MENU SOUND CHANGE BGM THEME SUMMARY: PASS")
