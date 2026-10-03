#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_update_falling.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPON_UPDATE_FALLING_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006ABB","0x00434E88","200001")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",164,"a6c62583dc93b0e5f367e45b8ea8bb2499f87333aa6f39cd3c666d188b973e44")
assert m["body_hex"]=="02257bd7b60004027bd8b60004283c00000a7dd7b6000402257bd4b60004027bd7b60004283c00000a7dd4b60004027cd4b600047b5600000a027bddb60004425f000000027cd4b60004027bddb600047d5600000a027cd7b60004257b5600000a229a9999be5a7d5600000a027cd7b600047b5600000a284500000a226f12033b421d00000002167dd5b6000402283d00000a7dd7b6000402283d00000a7dd8b600042a"
assert s["dll"]["internal_game_method_calls"]==[]
assert s["dll"]["direct_reference_count"]==1
assert s["dll"]["direct_caller_method_count"]==1
ref=s["dll"]["direct_in_assembly_references"][0]
assert (ref["caller_type"],ref["caller_method"],ref["call_il"],ref["opcode"])==("Weapon","UpdateWeapon","0x00A5","call")
sel=s["selection_boundary"]
sib=sel["competing_direct_child"]
assert (sib["token"],sib["method"],sib["code_size"],sib["direct_reference_count"],sib["direct_caller_method_count"],sib["update_weapon_call_il"])==("0x06006ABC","Update_ThrowIn",188,1,1,"0x0102")
assert sel["parent"]["code_size"]==351
c=s["capture_boundary"]
assert c["weapon_update_falling_row_count"]==0
assert c["weapon_update_weapon_row_count"]==0
assert c["weapon_update_throw_in_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPON UPDATE FALLING SUMMARY: PASS")
