#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_se_data_lookup.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_SE_DATA_LOOKUP_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005273","0x0032062D",25,"debaed5fa38ab512128db75e843d35f2df2d78e93145f1f7c9f88fb3ca2d7199")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(12,2,0)
assert s["dll"]["table_field"]=={"name":"MatchSEParamTbl","token":"0x0400866B"}
assert s["dll"]["raw_valid_range"]=={"min_inclusive":0,"max_inclusive":108}
assert [x["opcode"] for x in s["dll"]["exact_bounds"][:2]]==["blt","blt"]
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0060"
print("DLL MATCH SE DATA LOOKUP SUMMARY: PASS")
