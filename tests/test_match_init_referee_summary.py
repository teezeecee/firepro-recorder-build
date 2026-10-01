#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"match_init_referee.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_INIT_REFEREE_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["code_size"]) for x in m]==[("0x06004919",8),("0x06007425",523),("0x0600493F",8),("0x06007443",303)]
assert m[0]["code_sha256"]=="d404b794b4ad8b202e0dfaadeceb6698bcd0a653b27f42d05efb6c60d3692ad4"
assert m[1]["code_sha256"]=="2cf73d3b9e4f7c5d0e3e3bf24708c219538bab0e1dcac04dc076329b4002c98d"
assert m[2]["code_sha256"]=="42472ac9c0e12c47b372f848afebdd431149ffcf9d829a116b336d25e424ef29"
assert m[3]["code_sha256"]=="c5fc6e292c2adf300eeda5ad44d8c2e0d0650a59e63eadf41213ea81f90e1d6d"
assert s["dll"]["shared_raw_flow"]["edit_threshold"]==10000
assert s["dll"]["shared_raw_flow"]["costume_index"]==0
assert s["dll"]["shared_raw_flow"]["request_animation"]["raw_argument"]==1106
assert s["dll"]["match_main_path"]["raw_pc_dispatch"]==[0,1,2]
assert s["dll"]["match_main_path"]["first_yield"]["next_pc"]==1
assert s["dll"]["match_main_path"]["second_yield"]["next_pc"]==2
assert s["dll"]["match_main_cp_path"]["async_yields"]==0
assert s["dll"]["fact_0066_bridge"]["fact_id"]=="FACT-0066"
print("DLL MATCH INIT REFEREE SUMMARY: PASS")
