#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_gamepad_update.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_GAMEPAD_UPDATE_V1"
m=s["dll"]["method"]; t=s["dll"]["subtype"]
assert (t["typedef_rid"],t["extends_typedeforref_raw"],t["extends_rid"])==(2557,"0x27B8",2542)
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005035","0x003005EA",59,"7e6adb5aef2f2ce9384861ba006f6c2604af02cd16a87c245b92b5dee816658f")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"])==("0x00C6","0xEE")
assert m["body_hex"]=="027e00280004027bc5610004947d17610004027e01280004027bc5610004947d18610004027efa5e0004027b166100046f864e00067d196100042a"
assert [(x["call_il"],x["canonical_fact"]) for x in s["dll"]["canonical_internal_calls"]]==[("0x0030","FACT-0209")]
assert s["dll"]["direct_reference_count"]==0
assert [(x["type"],x["code_size"]) for x in s["dll"]["remaining_open_override_frontier"]]==[("PlayerController_Network",94),("PlayerController_Tutorial",352),("PlayerController_AI",984)]
c=s["capture_boundary"]
assert c["playercontroller_gamepad_update_row_count"]==0 and c["grapplehost_offline_result_row_count"]==0 and c["playercontroller_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER GAMEPAD UPDATE SUMMARY: PASS")
