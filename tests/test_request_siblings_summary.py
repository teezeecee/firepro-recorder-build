#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"request_siblings.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_FORMANIMATOR_REQUEST_SIBLINGS_V1"
a=s["dll"]["req_serial_anm"]; b=s["dll"]["req_skill_anm"]
assert a["token"]=="0x06004E6D" and a["rva"]=="0x002D9F13" and a["code_size"]==21
assert a["signature_blob_hex"]=="20010111a97c" and a["parameter"]=={"sequence":1,"name":"skill_id","type":"valuetype SkillAnmEnum"}
assert a["code_sha256"]=="ba11f4c9eb5c4039a8ba03055c42e707db927df9884b7e4a03d5ce45cc2b730e"
assert b["token"]=="0x06004E6E" and b["rva"]=="0x002D9F29" and b["code_size"]==21
assert b["signature_blob_hex"]=="20010111a9dc" and b["parameter"]=={"sequence":1,"name":"skill_id","type":"valuetype SkillID"}
assert b["code_sha256"]=="ac3eec081214a41850096a738ad0778366871ea77181e1fa20c4eb73915af81e"
q=s["dll"]["closed_request_type_initializer"]
assert set(q)=={"0","1","2","3"}
assert q["0"]["fact_id"]=="FACT-0010" and q["1"]["fact_id"]=="FACT-0009"
assert q["2"]["fact_id"]==q["3"]["fact_id"]=="FACT-0012"
assert s["dll"]["common_reset_target"]=={"method":"FormAnimator.InitAnmWork","token":"0x06004E6C","fact_id":"FACT-0011"}
print("DLL REQUEST SIBLINGS SUMMARY: PASS")
