#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_man_get_pl_obj.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_MAN_GET_PL_OBJ_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06005065","0x00304B6C","200112a78808")
assert (m["code_size"],m["code_sha256"])==(25,"32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8")
assert m["parameters"]==[{"sequence":1,"name":"idx","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(13,2,0)
assert s["dll"]["field"]["token"]=="0x040061FF"
assert s["dll"]["raw_valid_index_range"]=={"minimum":0,"maximum":7}
assert s["dll"]["fact_0108_bridge"]["call_il"]=="0x0016"
print("DLL PLAYER MAN GET PL OBJ SUMMARY: PASS")
