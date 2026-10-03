#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_update_base.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_UPDATE_BASE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004F97","0x002F5A67",1,"684888c0ebb17f374298b65ee2807526c066094c701bcc7ebbe1c1095f494fc1")
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["body_hex"])==("0x0000","0x01C6","2a")
assert m["method_attribute_bits"]==["Public","Virtual","HideBySig","NewSlot"]
assert s["dll"]["direct_reference_count"]==2 and s["dll"]["direct_caller_method_count"]==2
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[("Update_EntranceScene","0x006F","callvirt"),("Update_Match","0x0129","callvirt")]
c=s["capture_boundary"]
assert c["playercontroller_update_row_count"]==0 and c["matchmain_update_entrance_scene_row_count"]==0 and c["matchmain_update_match_row_count"]==0
assert c["promoted_as_evidence"] is False
assert s["dispatch_boundary"]["not_proven"].startswith("Which concrete PlayerController subtype")
print("DLL PLAYERCONTROLLER UPDATE BASE SUMMARY: PASS")
