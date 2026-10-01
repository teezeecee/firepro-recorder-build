#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_stop_bgm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_STOP_BGM_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052A4","0x003229E0","000001")
assert (m["code_size"],m["code_sha256"])==(59,"5ba3bf95e0ffa2db0c9766a6254c9016dab003ed26d580ec573effd8e2966b51")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(2,"0x1100120B","070112aa2c")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(19,1,3)
assert s["dll"]["calls"]["audio_src_stop"]["call_il"]=="0x0009"
assert s["dll"]["calls"]["destroy_audio_player"]["call_il"]=="0x0023"
assert s["dll"]["fact_0122_bridge"]["call_il"]=="0x0130"
print("DLL MENU SOUND STOP BGM SUMMARY: PASS")
