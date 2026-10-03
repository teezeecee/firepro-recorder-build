#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_update_weapon.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_UPDATE_WEAPON_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06006AD0","0x00435634",50,"35d1ad134ac75a73b958fd378c3a108d4911f9faddf0d99b383f0062de3c2b6a")
assert (m["local_signature_token"],m["local_signature_blob_hex"])==("0x11001611","07020812b508")
assert m["body_hex"]=="160a3823000000027becb60004069a0b07282a00000a3a050000003806000000076fbd6a00060617580a061e3fd6ffffff2a"
assert s["dll"]["fields"][0]["name"]=="WeaponObj" and s["dll"]["fields"][0]["decoded_type"]=="Weapon[]"
ci=s["dll"]["canonical_internal_calls"]
assert [(x["call_il"],x["canonical_fact"]) for x in ci]==[("0x0021","FACT-0204")]
assert s["dll"]["direct_reference_count"]==2 and s["dll"]["direct_caller_method_count"]==2
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_method"],x["call_il"]) for x in refs]==[("Update_EntranceScene","0x0242"),("Update_Match","0x03E8")]
c=s["capture_boundary"]
assert c["weaponman_update_weapon_row_count"]==0 and c["weapon_update_weapon_row_count"]==0
assert c["matchmain_update_entrance_scene_row_count"]==0 and c["matchmain_update_match_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPONMAN UPDATE WEAPON SUMMARY: PASS")
