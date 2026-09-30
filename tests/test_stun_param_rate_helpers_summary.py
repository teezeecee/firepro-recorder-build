#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"stun_param_rate_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_STUN_PARAM_RATE_HELPERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["signature_blob_hex"],a["code_size"],a["code_sha256"])==(
 "0x06004EDA","0x002E193F","20010108",27,"f1cf347336997ae6ca3fc68973801bfad9697cf43326c86143a6cfa7cbb96074")
assert a["parameters"]==[{"sequence":1,"name":"tm","type":"Int32"}]
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(11,1,0)
assert (b["token"],b["rva"],b["signature_blob_hex"],b["code_size"],b["code_sha256"])==(
 "0x06004975","0x002B0D74","00010c0c",16,"60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c")
assert b["parameters"]==[{"sequence":1,"name":"prm","type":"Float32"}]
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(8,0,0)
assert s["dll"]["set_stun_time"]["comparison_opcode"]=="bge" and s["dll"]["set_stun_time"]["raw_min"]==0
assert s["dll"]["get_param_rate"]["exact_expression"]=="prm / 65535.0f * 100.0f"
br=s["dll"]["fact_0030_bridge"]
assert [x["il"] for x in br["set_stun_time_calls"]]==["0x0018","0x0079","0x00F1"]
assert [x["argument"] for x in br["set_stun_time_calls"]]==["0","local2","960"]
assert [(x["il"],x["argument"]) for x in br["get_param_rate_calls"]]==[("0x00BC","this.HP"),("0x00D1","this.SP")]
print("DLL STUN/PARAM RATE HELPERS SUMMARY: PASS")
