#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_end_force_control.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_END_FORCE_CONTROL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004F75","0x002F2E9E",19,"4321518c766e7855fee13fe8c71e345755accee937ddefec62ce07a84efcb40f")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["header_format"],m["tiny_header_byte_raw"])==("9e2e2f00000086000c330a005c480000923a","200001","tiny","0x4E")
assert [(x["name"],x.get("raw_value")) for x in s["dll"]["fields"]]==[("forceControl",0),("plForcedController",None)]
assert s["dll"]["canonical_methoddef_calls"]==[{"fact_id":"FACT-0222","token":"0x06005040","method":"PlayerForcedController.End_FoceControl","sites":[{"il":"0x000D","opcode":"callvirt"}]}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(13,12)
assert s["dll"]["opcode_counts"]=={"call":0,"callvirt":13,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert s["dll"]["normalized_reference_map_sha256"]=="0d514dda57375578c8776e675b24e79cab34db6f1bca46569a65c9774c15d572"
assert s["dll"]["normalized_caller_token_set_sha256"]=="bb386065dcc6a0f7ba33c97d1afb993a7db3487c1279a253558f5982b3079136"
assert any(x["caller_token"]=="0x0600503D" and x["call_il"]=="0x0035" for x in s["dll"]["direct_in_assembly_references"])
c=s["capture_boundary"]
assert c["player_end_force_control_row_count"]==0 and c["playerforcedcontroller_end_foce_control_row_count"]==0 and c["playercontroller_tutorial_update_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_open_subtree"]
assert (n["parent_method"],n["parent_code_size"],n["child_method"],n["child_code_size"])==("Player.Start_ForceControl",20,"PlayerForcedController.Start_FoceControl",29)
print("DLL PLAYER END FORCE CONTROL SUMMARY: PASS")
