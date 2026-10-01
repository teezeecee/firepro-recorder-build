#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"create_referee_disp_awake.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_CREATE_REFEREE_DISP_AWAKE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600283D","0x0016B410","200001")
assert (m["code_size"],m["code_sha256"])==(203,"c6838190cec43f4419a3adb7d1d18f7d38e4810430ed454c346d422f8a8db9b4")
assert (m["max_stack"],m["local_signature_token"])==(4,"0x11000966")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(55,1,21)
assert s["dll"]["fields"]["parent_referee"]["token"]=="0x040032D6"
assert s["dll"]["fields"]["referee"]["token"]=="0x040032D7"
assert s["dll"]["strings"]["existing_parent_path"]["token"]=="0x7004AC4C"
assert s["dll"]["strings"]["dialog_camera_path"]["token"]=="0x7002DE90"
assert s["dll"]["strings"]["created_name"]["token"]=="0x7004ACB2"
assert s["dll"]["strings"]["layer_name"]["token"]=="0x7004ACDA"
assert s["dll"]["canonical_bridges"]["get_inst"]["call_il"]=="0x00BB"
assert s["dll"]["canonical_bridges"]["create_referee"]["call_il"]=="0x00C0"
print("DLL CREATE REFEREE DISP AWAKE SUMMARY: PASS")
