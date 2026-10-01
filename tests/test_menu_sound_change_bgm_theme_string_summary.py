#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_change_bgm_theme_string.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_CHANGE_BGM_THEME_STRING_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06005298","0x00322430","0003010e0202")
assert (m["code_size"],m["code_sha256"])==(125,"3d1bd7f767849f9b77dd562c223725e3f1614d823843c55b71a12d7b15303c18")
assert (m["max_stack"],m["local_signature_token"])==(5,"0x11001204")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(37,2,7)
assert s["dll"]["strings_and_constants"]["resource_prefix"]["value"]=="Sound/Bgm/"
assert s["dll"]["strings_and_constants"]["system_sound_raw"]==33
assert s["dll"]["calls"]["get_instance"]["fact_id"]=="FACT-0112"
assert s["dll"]["calls"]["co_change"]["fact_id"]=="FACT-0115"
assert s["dll"]["calls"]["audio_clip_set"]["fact_id"]=="FACT-0113"
assert s["dll"]["fact_0122_bridge"]["call_il"]=="0x00F0"
print("DLL MENU SOUND CHANGE BGM THEME STRING SUMMARY: PASS")
