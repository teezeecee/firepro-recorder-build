#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_change_current_volume.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_CHANGE_CURRENT_VOLUME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052E0","0x0032587C","2001010c")
assert (m["code_size"],m["code_sha256"])==(8,"bf7afe343990f70067b2d0a5f418a180d7f1abee664827c4b4e6e18940403ca7")
assert m["parameters"]==[{"sequence":1,"name":"volumeIN","type":"Single"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,1)
assert s["dll"]["call"]["token"]=="0x060052DC"
assert [x["call_il"] for x in s["dll"]["fact_0133_bridges"]]==["0x0105","0x01BC"]
print("DLL U AUDIO CHANGE CURRENT VOLUME SUMMARY: PASS")
