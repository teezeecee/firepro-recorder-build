#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_update_throw_in.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPON_UPDATE_THROW_IN_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006ABC","0x00434F38","200001")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",188,"0c414a06ab008a72015d27a098c79d068c39a442248446c4245d541423a35bf1")
assert (m["local_signature_token"],m["local_signature_blob_hex"])==("0x1100001F","07010c")
assert m["body_hex"]=="02257bd7b60004027bd8b60004283c00000a7dd7b60004027cd7b60004257b0900000a027bd9b600045a7d0900000a027cd7b60004257b0a00000a027bd9b600045a7d0a00000a02257bd4b60004027bd7b60004283c00000a7dd4b60004027cd7b600047b0900000a027cd7b600047b0900000a5a027cd7b600047b0a00000a027cd7b600047b0a00000a5a5828b609000a0a06226f12033b421d00000002167dd5b6000402283d00000a7dd7b6000402283d00000a7dd8b600042a"
assert s["dll"]["internal_game_method_calls"]==[]
assert s["dll"]["direct_reference_count"]==1
assert s["dll"]["direct_caller_method_count"]==1
ref=s["dll"]["direct_in_assembly_references"][0]
assert (ref["caller_method"],ref["call_il"],ref["opcode"])==("UpdateWeapon","0x0102","call")
sel=s["selection_boundary"]["parent"]
assert sel["method"]=="UpdateWeapon" and sel["code_size"]==351
assert [x["canonical_fact"] for x in sel["direct_methoddef_call_patterns"]]==["FACT-0201","FACT-0202",None]
c=s["capture_boundary"]
assert c["weapon_update_throw_in_row_count"]==0
assert c["weapon_update_weapon_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPON UPDATE THROW IN SUMMARY: PASS")
