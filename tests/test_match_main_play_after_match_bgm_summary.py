#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_main_play_after_match_bgm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_MAIN_PLAY_AFTER_MATCH_BGM_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06004925","0x002A96A8","200001")
assert (m["code_size"],m["code_sha256"])==(390,"ce8a2a91a564c9f28928b39c7d444dfe0758d3b771b7a142125e5bac4daaa2b5")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(3,"0x11000F48","070212a40802")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(123,22,10)
assert s["dll"]["strings"]["default_after_match_bgm"]["value"]=="BGIN_001"
assert s["dll"]["calls"]["check_file"]["call_ils"]==["0x010D"]
assert s["dll"]["calls"]["change_bgm_theme_id"]["call_ils"]==["0x011A","0x0167","0x0174"]
assert s["dll"]["calls"]["my_music_set"]["call_ils"]==["0x0126","0x013D","0x0180"]
print("DLL MATCH MAIN PLAY AFTER MATCH BGM SUMMARY: PASS")
