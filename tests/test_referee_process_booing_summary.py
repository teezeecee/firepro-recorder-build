#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_process_booing.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_PROCESS_BOOING_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050A3","0x00308FB4",90,"b7e8964816ea334e17fdf26aeb44a9789251e264d1bcc2eedc1fbd0fcc3ea42d")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(29,2,2)
assert s["dll"]["calls"][0]["raw_arguments"]==[9,0]
assert s["dll"]["calls"][1]["raw_arguments"]==[]
assert s["dll"]["fact_0074_bridge"]["call_il"]=="0x0033"
print("DLL REFEREE PROCESS BOOING SUMMARY: PASS")
