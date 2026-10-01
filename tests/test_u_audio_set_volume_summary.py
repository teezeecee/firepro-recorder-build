#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_set_volume.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SET_VOLUME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052DC","0x00325827","2001010c")
assert (m["code_size"],m["code_sha256"])==(13,"e3434a65b5c1a9c14959c686924c525e57f68f1cf3fbde7c02a25819e891480c")
assert m["parameters"]==[{"sequence":1,"name":"value","type":"Single"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(5,0,1)
assert s["dll"]["field"]["token"]=="0x040087E4"
assert s["dll"]["call"]["token"]=="0x0A0002A2"
assert s["dll"]["fact_0134_bridge"]["call_il"]=="0x0002"
print("DLL U AUDIO SET VOLUME SUMMARY: PASS")
