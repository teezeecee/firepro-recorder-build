#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playerforcedcontroller_end_foce_control.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERFORCEDCONTROLLER_END_FOCE_CONTROL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005040","0x00300938",22,"4bce19fe9959b584ef14908126404a2afd4c862fc4d271de03b82729964915a3")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["header_format"],m["tiny_header_byte_raw"])==("38093000000086007f400a005c480000ef3a","200001","tiny","0x5A")
assert [(x["name"],x["raw_value"]) for x in s["dll"]["fields"]]==[("mode",0),("step",0),("isComplete",1)]
assert s["dll"]["internal_methoddef_calls"]==[]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(3,2)
assert s["dll"]["normalized_reference_map_sha256"]=="2c3426da596fc724458f6d3cdcc1e461081535933d89e2968b6dff0b9c190dec"
assert [(x["caller_token"],x["call_il"],x["opcode"]) for x in s["dll"]["direct_in_assembly_references"]]==[("0x06004F75","0x000D","callvirt"),("0x06005055","0x010B","call"),("0x06005055","0x012C","call")]
c=s["capture_boundary"]
assert c["playerforcedcontroller_end_foce_control_row_count"]==0 and c["player_end_force_control_row_count"]==0 and c["playerforcedcontroller_make_key_data_force_control_row_count"]==0 and c["playercontroller_tutorial_update_row_count"]==0 and c["promoted_as_evidence"] is False
f=s["selection_boundary"]["dispatch_frontier"]
assert [x["fact_id"] for x in f["already_canonical_overrides"]]==["FACT-0207","FACT-0208","FACT-0210","FACT-0221"]
assert [x["token"] for x in f["remaining_open_overrides"]]==["0x0600503D","0x0600502B"]
assert s["selection_boundary"]["next_parent_candidate"]["token"]=="0x06004F75"
print("DLL PLAYERFORCEDCONTROLLER END FOCE CONTROL SUMMARY: PASS")
