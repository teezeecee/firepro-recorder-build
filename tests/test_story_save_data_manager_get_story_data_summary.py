#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"story_save_data_manager_get_story_data.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_STORY_SAVE_DATA_MANAGER_GET_STORY_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06003C24","0x0023A1BD","2000129cd4")
assert (m["code_size"],m["code_sha256"])==(12,"564cd017b6b587e05dc90b0c95294394b6d0d874e7c59dee6c493fa3182cb611")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,1)
assert s["dll"]["exact_body"][1]["token"]=="0x04004856"
assert s["dll"]["exact_body"][2]["token"]=="0x06003C25"
assert s["dll"]["sibling_dependency"]["signature_blob_hex"]=="2001129cd4119cd0"
assert s["dll"]["fact_0101_bridge"]["manager_load_il"]=="0x001C"
assert s["dll"]["fact_0101_bridge"]["call_il"]=="0x0021"
print("DLL STORY SAVE DATA MANAGER GET STORY DATA SUMMARY: PASS")
