#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"get_health.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_GET_HEALTH_V1"
m=s["dll"]["method"]
assert m["token"]=="0x0600495C" and m["rva"]=="0x002B0270"
assert m["signature_blob_hex"]=="0001080c" and m["return_type"]=="Int32"
assert m["parameters"]==[{"sequence":1,"name":"prm","type":"Float32"}]
assert m["code_size"]==204 and m["code_sha256"]=="54a177d606676d55511eb6a20680babd8298b5f520b47aa6109a77df9eac50ec"
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(77,15,0)
lad=s["dll"]["ladder"]; assert lad["branch_opcode"]=="bge.un" and lad["final_return"]==15
assert [x["threshold"] for x in lad["rungs"]]==[4096,8192,12288,16384,20480,24576,28672,32768,36864,40960,45056,49152,53248,57344,61440]
assert [x["fallthrough_return"] for x in lad["rungs"]]==list(range(15))
assert s["dll"]["caller_bridges"][0]["fact_id"]=="FACT-0021" and len(s["dll"]["caller_bridges"][0]["call_ils"])==6
assert s["dll"]["caller_bridges"][1]["fact_id"]=="FACT-0022"
print("DLL GET HEALTH SUMMARY: PASS")
