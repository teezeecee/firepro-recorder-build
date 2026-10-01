#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"ai_init_all_works.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_INIT_ALL_WORKS_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06004F9A","0x002F5DF0","20010102",213,"f79b47e5840d3c2948b9ce1a4af92f400b37f9fa52d613a9fb2a5b91674edeee")
assert m["parameters"]==[{"sequence":1,"name":"create_init","type":"Boolean"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(89,1,3)
assert len(s["dll"]["zero_fields"])==21
assert [x["name"] for x in s["dll"]["minus_one_fields"]]==["destCorner","currentPriAct","touchTarget"]
assert s["dll"]["shared_timer_value"]["raw_value"]==216000
assert [(x["method"],x["il"]) for x in s["dll"]["helper_calls"]]==[
 ("Reset_HungUpCheck","0x00B6"),("ResetCheckedPriAct","0x00BC"),("CalcTouchTime","0x00C8")]
assert s["dll"]["caller_bridge"]["raw_argument"] is True
print("DLL AI INIT ALL WORKS SUMMARY: PASS")
