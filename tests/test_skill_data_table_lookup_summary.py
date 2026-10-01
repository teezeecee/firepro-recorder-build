#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"skill_data_table_lookup.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SKILL_DATA_TABLE_LOOKUP_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005262","0x0031FEC5","200112a9a811a97c",30,"34bf8ce8e06453d321e7f41685aa3e4e372936c5a0c79f789966d562be26b88b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(13,2,0)
assert s["dll"]["exact_bounds"]["valid_raw_range"]=={"min_inclusive":0,"max_inclusive":4187}
assert s["dll"]["exact_bounds"]["fallback_opcode"]=="starg.s"
assert s["dll"]["lookup"]=={"field":{"name":"skillData","token":"0x04007CF7"},"effect":"return skillData[anm_id]"}
assert s["dll"]["fact_0072_bridge"]["call_il"]=="0x0008"
print("DLL SKILL DATA TABLE LOOKUP SUMMARY: PASS")
