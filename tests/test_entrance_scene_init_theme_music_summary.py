#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"entrance_scene_init_theme_music.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_ENTRANCE_SCENE_INIT_THEME_MUSIC_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06004833","0x00299808","200001")
assert (m["code_size"],m["code_sha256"])==(244,"c64099c6e74a32eaa9dcc01c14768a9687140d2da506f443bd11da9449a5bb58")
assert (m["max_stack"],m["local_signature_token"])==(3,"0x11000EED")
assert m["local_signature_blob_hex"]=="07050812a78812a40812a4041287b4"
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(76,8,9)
assert s["dll"]["raw_values"]=={"theme_threshold":10000,"story_sentinel":-2,"my_music_set_index":33,"change_bgm_boolean_args":[False,False]}
assert s["dll"]["calls"]["get_edit_wrestler_data"]["call_il"]=="0x0084"
assert s["dll"]["calls"]["get_story_data"]["call_il"]=="0x0098"
assert s["dll"]["calls"]["check_file"]["call_il"]=="0x00AB"
assert s["dll"]["calls"]["change_bgm_theme"]["call_ils"]==["0x003E","0x00B8","0x00EE"]
assert s["dll"]["calls"]["my_music_set"]["call_ils"]==["0x00C4","0x00D7"]
print("DLL ENTRANCE SCENE INIT THEME MUSIC SUMMARY: PASS")
