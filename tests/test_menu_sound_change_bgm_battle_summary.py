#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_change_bgm_battle.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_CHANGE_BGM_BATTLE_V1"
m=s["dll"]["change_bgm_battle"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600529A","0x003224E8","00030111a9f00202")
assert (m["code_size"],m["code_sha256"])==(327,"4ad21fa3a9b1dd5d1b2e36c8c169c7d9809a762ca4958bbb3649036346facc9e")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(100,8,24)
assert m["canonical_calls"]["cochange_assetbundle"]["call_il"]=="0x0046"
assert m["canonical_calls"]["cochange_resource"]["call_il"]=="0x006F"
assert m["canonical_calls"]["audio_clip_set"]["call_ils"]==["0x00CD","0x0104","0x0134"]
g=s["dll"]["get_bgm_info_match"]
assert (g["token"],g["rva"],g["code_size"],g["code_sha256"])==("0x0600526F","0x00320266",8,"46a9d4d199f469f19a3c443ea30af3a1a2d46348d9781332c319c4a5d83f9b3c")
assert g["body_hex"]=="7e2e860004029a2a"
assert s["dll"]["fact_0161_bridge"]["call_il"]=="0x0024"
print("DLL MENU SOUND CHANGE BGM BATTLE SUMMARY: PASS")
