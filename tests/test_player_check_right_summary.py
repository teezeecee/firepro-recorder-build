#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_check_right.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_CHECK_RIGHT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004EB9","0x002DE7BC",28,"91e367c3dde890584416fa256d52fe2122dde68fa653733621274d624b4002f1")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(12,2,0)
assert s["dll"]["fields"]==[{"name":"isLose","token":"0x04006052"},{"name":"hasRight","token":"0x04006043"}]
assert s["dll"]["equivalent_true_condition"]=="isLose == 0 AND hasRight != 0"
assert s["dll"]["fact_0093_bridge"]["call_il"]=="0x003C"
print("DLL PLAYER CHECK RIGHT SUMMARY: PASS")
