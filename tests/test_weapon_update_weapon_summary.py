#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_update_weapon.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPON_UPDATE_WEAPON_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06006ABD","0x00435000",351,"e8abda8319bdbcd424c4a521ed8decbb056271a54e759da39759a0eb46748263")
assert (m["local_signature_token"],m["local_signature_blob_hex"])==("0x1100160D","07030c0c11b500")
assert m["body_hex"]=="220000803f0a220000803f0b027bdbb60004193f080000000622000080bf5a0a027bd5b600040c084504000000050000005c00000067000000c4000000381c01000002282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a38c50000000228ba6a000638ba0000000228bb6a000602282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a385d0000000228bc6a000602282800000a6f5000000a027cd4b600047b0900000a027cd4b600047b5600000a027cd4b600047b0a00000a734400000a6f7a00000a02282800000a6f5000000a0607220000803f734400000a6f5d00000a38000000002a"
assert [(x["call_il"],x["canonical_fact"]) for x in s["dll"]["canonical_internal_calls"]]==[("0x009A","FACT-0201"),("0x00A5","FACT-0202"),("0x0102","FACT-0203")]
assert s["dll"]["direct_reference_count"]==1 and s["dll"]["direct_caller_method_count"]==1
ref=s["dll"]["direct_in_assembly_references"][0]
assert (ref["caller_type"],ref["caller_method"],ref["call_il"],ref["opcode"])==("WeaponMan","UpdateWeapon","0x0021","callvirt")
c=s["capture_boundary"]
assert c["weapon_update_weapon_row_count"]==0 and c["weaponman_update_weapon_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_direct_caller"]
assert (n["method"],n["code_size"],n["direct_reference_count"],n["direct_caller_method_count"])==("UpdateWeapon",50,2,2)
print("DLL WEAPON UPDATE WEAPON SUMMARY: PASS")
