#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_field_getters.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_FIELD_GETTERS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["field_token"]) for x in m]==[
 ("0x060052CE","0x003256A9","0x040087F0"),
 ("0x060052DF","0x00325874","0x040087E9"),
 ("0x060052E1","0x00325885","0x040087E6")]
assert [x["code_size"] for x in m]==[7,7,7]
assert [x["signature_blob_hex"] for x in m]==["20000c","20001182b5","20000e"]
print("DLL U AUDIO FIELD GETTERS SUMMARY: PASS")
