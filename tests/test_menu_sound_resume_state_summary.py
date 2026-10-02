#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_resume_state.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_RESUME_STATE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06005281","0x003218E4","000001")
assert (m["code_size"],m["code_sha256"])==(42,"a9e694a8e4472424719df74de8cf44737e837e6a86bc7e5dfd2a29c6ee47931a")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(14,0,4)
calls=s["dll"]["direct_calls"]
assert [(calls[k]["token"],calls[k]["call_il"]) for k in ["update_state","change_bgm_progress","change_bgm_theme","change_bgm_battle"]]==[
 ("0x06005282","0x0000"),("0x06005292","0x000C"),("0x06005296","0x0018"),("0x0600529A","0x0024")]
fields=s["dll"]["static_fields"]
assert [(fields[k]["token"],fields[k]["load_il"]) for k in ["progress","admission","battle"]]==[
 ("0x0400286D","0x0005"),("0x0400286E","0x0011"),("0x0400286F","0x001D")]
assert s["dll"]["fact_0160_bridge"]["call_il"]=="0x0092"
print("DLL MENU SOUND RESUME STATE SUMMARY: PASS")
