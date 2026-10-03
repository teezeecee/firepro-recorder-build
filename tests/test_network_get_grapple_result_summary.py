#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"network_get_grapple_result.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_NETWORK_GET_GRAPPLE_RESULT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004B58","0x002C23F5",9,"96fe199528ac76a9fff0c97bc3756699c17bad16faee068b22be044a933242da")
assert (m["tiny_header_byte_raw"],m["body_hex"])==("0x26","027b8f5a0004039a2a")
assert s["dll"]["field"]["token"]=="0x04005A8F" and s["dll"]["field"]["name"]=="grappleResultWork"
assert s["dll"]["internal_game_method_calls"]==[]
assert s["dll"]["direct_reference_count"]==2 and s["dll"]["direct_caller_method_count"]==2
assert [(x["caller_method"],x["call_il"]) for x in s["dll"]["direct_in_assembly_references"]]==[("Prepare","0x0016"),("Update","0x0053")]
c=s["capture_boundary"]
assert c["network_get_grapple_result_row_count"]==0 and c["playercontroller_network_update_row_count"]==0 and c["playercontroller_ai_prepare_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL NETWORK GET GRAPPLE RESULT SUMMARY: PASS")
