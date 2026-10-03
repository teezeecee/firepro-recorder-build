#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_nocontrol_update.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_NOCONTROL_UPDATE_V1"
m=s["dll"]["method"]; t=s["dll"]["subtype"]
assert (t["typedef_rid"],t["extends_typedeforref_raw"],t["extends_rid"])==(2559,"0x27B8",2542)
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600503A","0x003006D8",15,"1fb22e770dcbf84240bd60523215799d14585f3c5de15394803c5bffb8944298")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"],m["body_hex"])==("0x00C6","0x3E","02167d1761000402167d186100042a")
assert [(x["name"],x["token"]) for x in s["dll"]["inherited_fields"]]==[("padOn","0x04006117"),("padPush","0x04006118")]
assert s["dll"]["direct_reference_count"]==0
assert [(x["type"],x["code_size"]) for x in s["dll"]["remaining_open_override_frontier"]]==[("PlayerController_GamePad",59),("PlayerController_Network",94),("PlayerController_Tutorial",352),("PlayerController_AI",984)]
c=s["capture_boundary"]; assert c["playercontroller_update_row_count"]==0 and c["playercontroller_nocontrol_update_row_count"]==0 and c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER NOCONTROL UPDATE SUMMARY: PASS")
