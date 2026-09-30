#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"rate100_check.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_RATE100_CHECK_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06004955","0x002AFD54","00010208",38,"6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58")
assert m["parameters"]==[{"sequence":1,"name":"rt","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(17,2,3)
body=s["dll"]["exact_body"]
assert body[0]["range_token"]=="0x0600497B" and body[0]["raw_min"]==0 and body[0]["raw_max"]==100
assert body[1]["get_inst_token"]=="0x06004907" and body[1]["object_equality_memberref"]=="0x0A000006"
assert body[2]["comparison_opcode"]=="ble" and body[2]["operand_order"]==["rt","sample"]
assert body[2]["true_condition_int32"]=="rt > sample" and body[2]["false_condition_int32"]=="rt <= sample"
assert s["dll"]["apply_damage_bridge"]["fact_id"]=="FACT-0020"
assert [x["il"] for x in s["dll"]["apply_damage_bridge"]["calls"]]==["0x0498","0x04FE"]
print("DLL RATE100 CHECK SUMMARY: PASS")
