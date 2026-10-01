#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"save_data_story_data_getter.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SAVE_DATA_STORY_DATA_GETTER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005172","0x003149AB",11,"6ae14bc58bd6ce5fef923aed7dc39a940d5975700065175c076beda7f3ff143e")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(3,0,1)
assert s["dll"]["exact_body"][0]["token"]=="0x06005171"
assert s["dll"]["exact_body"][1]["token"]=="0x0400485C"
assert s["dll"]["fact_0096_bridge"]["call_il"]=="0x0071"
print("DLL SAVE DATA STORY DATA GETTER SUMMARY: PASS")
