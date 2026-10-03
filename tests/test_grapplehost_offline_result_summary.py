#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"grapplehost_offline_result.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_GRAPPLEHOST_OFFLINE_RESULT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004E86","0x002DBC7D",25,"bf842a3657431d2f1f462688a7c150fe32593bd1a4db78283487cfcd576cedf0")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"])==("0x0086","0x66")
assert m["body_hex"]=="03163f07000000031e3f02000000142a027bfc5e0004039a2a"
assert s["dll"]["field"]["token"]=="0x04005EFC" and s["dll"]["field"]["name"]=="grappleResult"
assert s["dll"]["internal_game_method_calls"]==[]
assert s["dll"]["direct_reference_count"]==2 and s["dll"]["direct_caller_method_count"]==2
assert [(x["caller_method"],x["call_il"]) for x in s["dll"]["direct_in_assembly_references"]]==[("Prepare","0x0031"),("Update","0x0030")]
c=s["capture_boundary"]
assert c["grapplehost_offline_result_row_count"]==0 and c["playercontroller_gamepad_update_row_count"]==0 and c["playercontroller_ai_prepare_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL GRAPPLEHOST OFFLINE RESULT SUMMARY: PASS")
