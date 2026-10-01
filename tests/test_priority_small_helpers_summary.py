#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"priority_small_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PRIORITY_SMALL_HELPERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==(
 "0x06004F9B","0x002F5ED4",49,"9c943eda48fd9f9c76271366324f22095426c06b0eecbb77d37e0cc945dde6c3")
assert a["parameters"]==[{"sequence":1,"name":"hp","type":"Float32"}]
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(21,2,1)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==(
 "0x06004FD8","0x002F91A0",55,"9bea2fa5e79dc6e2c45acd5a83161a0ce0bec614c28ca0c2f0e63037bb0b2e01")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(23,2,1)
g=s["dll"]["get_damage_level_lmh"]
assert g["get_param_rate_fact_id"]=="FACT-0031"
assert [(x["index"],x["opcode"],x["non_branch_return_raw"]) for x in g["exact_branches"]]==[(0,"blt.un",0),(1,"blt.un",1)]
assert g["final_return_raw"]==2
r=s["dll"]["reset_hung_up_check"]
assert r["raw_index_range"]=={"min_inclusive":0,"max_inclusive":7}
assert r["loop_condition"]=="signed index < 8"
assert [x["il"] for x in s["dll"]["process_priority_act_bridge"]["calls"]]==["0x00E3","0x0190"]
print("DLL PRIORITY SMALL HELPERS SUMMARY: PASS")
