#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_get_u_audio_callback.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_GET_U_AUDIO_CALLBACK_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052EE","0x00325F6A","2001011182b5")
assert (m["code_size"],m["code_sha256"])==(13,"124f59a872afec501c29839a33e627e58a6c5339d59456ad7f66f6b7323e237d")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(5,0,1)
assert s["dll"]["field"]["token"]=="0x040087E7"
assert s["dll"]["call"]["token"]=="0x0A000FC4"
assert s["dll"]["fact_0138_bridge"]["ldftn_il"]=="0x003F"
print("DLL U AUDIO GET U AUDIO CALLBACK SUMMARY: PASS")
