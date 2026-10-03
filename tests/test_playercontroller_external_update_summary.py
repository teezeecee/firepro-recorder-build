#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_external_update.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_EXTERNAL_UPDATE_V1"
t=s["dll"]["subtype"]; m=s["dll"]["method"]
assert (t["typedef_rid"],t["extends_typedeforref_raw"],t["extends_rid"])==(2556,"0x27B8",2542)
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005032","0x003005B8",1,"684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1")
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["body_hex"])==("0x0000","0x00C6","2a")
assert m["method_attribute_bits"]==["Public","Virtual","HideBySig"] and m["newslot_bit_set"] is False
assert s["dll"]["direct_reference_count"]==0 and s["dll"]["direct_caller_method_count"]==0
f=s["dll"]["override_frontier"]
assert [(x["type"],x["code_size"]) for x in f]==[("PlayerController_External",1),("PlayerController_NoControl",15),("PlayerController_GamePad",59),("PlayerController_Network",94),("PlayerController_Tutorial",352),("PlayerController_AI",984)]
c=s["capture_boundary"]
assert c["playercontroller_update_row_count"]==0 and c["playercontroller_external_update_row_count"]==0
assert c["matchmain_update_entrance_scene_row_count"]==0 and c["matchmain_update_match_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER EXTERNAL UPDATE SUMMARY: PASS")
