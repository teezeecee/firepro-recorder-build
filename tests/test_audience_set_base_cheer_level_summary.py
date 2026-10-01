#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audience_set_base_cheer_level.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIENCE_SET_BASE_CHEER_LEVEL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060047D8","0x0028FE76",54,"aeedc6c70baddc6ef42cd4c445d568061fdc8a73a18464494aad0e9062279520")
assert m["parameters"]==[{"sequence":1,"name":"nLevel","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(20,2,1)
assert s["dll"]["field"]=={"name":"CheerLevel_Base","token":"0x040054CB"}
assert s["dll"]["clamp"]=={"min_inclusive":-4,"max_inclusive":4}
assert s["dll"]["calc_cheer_level"]["fact_id"]=="FACT-0083"
assert s["dll"]["fact_0093_bridge"]["raw_argument"]==4
print("DLL AUDIENCE SET BASE CHEER LEVEL SUMMARY: PASS")
