#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"fade_is_fade_finish.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_FADE_IS_FADE_FINISH_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004A7D","0x002B76FD",16,"8ab025c02e60a82d0238a60fbf523b6ad20647ca0ed32600a0fdf8b2df1a0083")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(8,1,0)
assert s["dll"]["field"]=={"name":"NowFrm","token":"0x04005920"}
assert s["dll"]["exact_branch"]["opcode"]=="bgt"
assert s["dll"]["exact_branch"]["equivalent_true_condition"]=="NowFrm <= 0"
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0058"
print("DLL FADE IS FADE FINISH SUMMARY: PASS")
