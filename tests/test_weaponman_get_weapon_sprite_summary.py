#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_get_weapon_sprite.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_GET_WEAPON_SPRITE_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006ACD","0x004355A0","2002121511b50408")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",98,"38d479af573bd1d4c4f72ad8947250d2ef5e4353f720d8c431daa0e3551dfb35")
assert m["body_hex"]=="040a03450c00000005000000050000000c0000000c0000000c0000000c0000000c00000015000000150000001500000015000000050000003817000000040a3810000000041c5d0a3807000000160a3800000000027bedb600040306287011000a2a"
f=s["dll"]["field"]
assert (f["token"],f["owner"],f["name"],f["signature_blob_hex"],f["decoded_type"])==("0x0400B6ED","WeaponMan","WeaponSprite","061412150200020000","UnityEngine.Sprite[,]")
g=s["dll"]["array_get_member"]
assert (g["token"],g["name"],g["signature_blob_hex"],g["call_il"])==("0x0A001170","Get","200212150808","0x005C")
assert s["dll"]["switch"]["raw_case_targets"]=={
 "0":"pat","1":"pat","2":"pat % 6","3":"pat % 6","4":"pat % 6","5":"pat % 6","6":"pat % 6",
 "7":"0","8":"0","9":"0","10":"0","11":"pat"
}
assert s["dll"]["switch"]["default"]=="pat"
assert s["dll"]["direct_reference_count"]==4
assert s["dll"]["direct_caller_method_count"]==4
assert len(s["dll"]["direct_in_assembly_references"])==4
canon={(x.get("canonical_fact"),x["caller_type"],x["caller_method"],x["call_il"]) for x in s["dll"]["direct_in_assembly_references"] if x.get("canonical_fact")}
assert canon=={("FACT-0196","Weapon","SetPattern","0x0021")}
c=s["capture_boundary"]
assert c["weaponman_get_weapon_sprite_row_count"]==0
assert c["partsallbtn_set_btn_idx_row_count"]==0
assert c["formrenderer_craft_set_form_row_count"]==0
assert c["formrenderer_craft_set_atk_rang_form_row_count"]==0
assert c["weapon_set_pattern_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPONMAN GET WEAPON SPRITE SUMMARY: PASS")
