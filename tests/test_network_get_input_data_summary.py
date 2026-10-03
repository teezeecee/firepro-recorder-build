#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"network_get_input_data.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_NETWORK_GET_INPUT_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004B49","0x002C1EB8",47,"cc873352d36cbd8a43a791fa41ddce1e8815f39b47564fa45f6645c3f53565bd")
assert (m["local_signature_token"],m["local_signature_blob_hex"])==("0x11000FBB","07030811a5ac11a5ac")
assert m["body_hex"]=="030a027b8a5a0004069a6f2c0e000a3a0a0000001201fe156b090002072a027b8a5a0004069a166f2d0e000a0c082a"
assert s["dll"]["field"]["token"]=="0x04005A8A" and s["dll"]["field"]["name"]=="m_InputBuffer"
assert [(x["name"],x["call_il"]) for x in s["dll"]["external_member_refs"]]==[("get_Count","0x000A"),("get_Item","0x0027")]
assert s["dll"]["internal_game_method_calls"]==[]
assert s["dll"]["direct_reference_count"]==1 and s["dll"]["direct_caller_method_count"]==1
assert s["dll"]["direct_in_assembly_references"][0]["call_il"]=="0x001A"
c=s["capture_boundary"]
assert c["network_get_input_data_row_count"]==0 and c["playercontroller_network_update_row_count"]==0 and c["promoted_as_evidence"] is False
print("DLL NETWORK GET INPUT DATA SUMMARY: PASS")
