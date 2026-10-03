#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_delete_weapon.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_DELETE_WEAPON_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AC6","0x00435394","20010108")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",57,"8855138052c3fa6baf7847766f20a3ff5ded2a517364b594dc4a7af747239be1")
assert m["body_hex"]=="03163f07000000031e3f010000002a027becb60004039a0a06282a00000a3a010000002a066f2800000a286f11000a027becb600040314a22a"
f=s["dll"]["field"]
assert (f["token"],f["owner"],f["name"],f["signature_blob_hex"],f["decoded_type"])==("0x0400B6EC","WeaponMan","WeaponObj","061d12b508","Weapon[]")
members={(x["token"],x["owner"],x["name"],x["signature_blob_hex"],x["call_il"]) for x in s["dll"]["external_member_refs"]}
assert members=={
 ("0x0A00002A","UnityEngine.Object","op_Implicit","0001021269","0x0019"),
 ("0x0A000028","UnityEngine.Component","get_gameObject","2000120d","0x0025"),
 ("0x0A00116F","UnityEngine.Object","DestroyObject","0001011269","0x002A")
}
assert s["dll"]["direct_reference_count"]==3
assert s["dll"]["direct_caller_method_count"]==3
refs={(x["caller_type"],x["caller_method"],x["call_il"],x["opcode"]) for x in s["dll"]["direct_in_assembly_references"]}
assert refs=={
 ("Player","ProcessAttackHit_Normal","0x013C","callvirt"),
 ("Weapon","Update_Equipped","0x0027","callvirt"),
 ("WeaponMan","DeleteAllWeapons","0x0009","call")
}
c=s["capture_boundary"]
assert c["weaponman_delete_weapon_row_count"]==0
assert c["player_process_attack_hit_normal_row_count"]==0
assert c["weapon_update_equipped_row_count"]==0
assert c["weaponman_delete_all_weapons_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPONMAN DELETE WEAPON SUMMARY: PASS")
