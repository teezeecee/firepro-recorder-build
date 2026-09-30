#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"skill_slot_data_lookup.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SKILL_SLOT_DATA_LOOKUP_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x0600116D","0x0006A234","000112870411870c",25,"fd2a546fcbc44dcd97c1376e5f5ba1802555f5b7f8c21d8ab3c123b3cf7fc0f0")
assert m["parameters"]==[{"sequence":1,"name":"slot","type":"SkillSlotEnum"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(12,2,0)
assert s["dll"]["table_field"]=={"name":"SkillSlotDataTbl","token":"0x04000EE7"}
assert s["dll"]["raw_valid_range"]=={"min_inclusive":0,"max_inclusive":90}
assert [x["opcode"] for x in s["dll"]["exact_bounds"][:2]]==["blt","blt"]
assert s["dll"]["fact_0024_bridge"]["call_il"]=="0x000E"
print("DLL SKILL SLOT DATA LOOKUP SUMMARY: PASS")
