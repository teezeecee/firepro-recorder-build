#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_update_equipped.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPON_UPDATE_EQUIPPED_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006ABA","0x00434E20","200001")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",92,"3aa49b941ea49de68211c6b8bd98672b796ea36dc5eb99deeae75ef911aa737d")
assert m["body_hex"]=="285d500006027bdcb600046f655000060a06282a00000a3a1100000028c06a0006027bd2b600046fc66a00062a02067bee5f00047ddab6000402167ddbb6000402282800000a067ba75f00047b3127000428764800066fd700000a2a"
calls={(x["token"],x["owner"],x["method"],x["call_il"],x.get("canonical_fact")) for x in s["dll"]["internal_game_method_calls"]}
assert calls=={
 ("0x0600505D","PlayerMan","GetInst","0x0000",None),
 ("0x06005065","PlayerMan","GetPlObj","0x000B","FACT-0109"),
 ("0x06006AC0","WeaponMan","GetInst","0x001C","FACT-0197"),
 ("0x06006AC6","WeaponMan","DeleteWeapon","0x0027","FACT-0199"),
 ("0x06004876","LayerMan","GetLayerID","0x0051","FACT-0057")
}
assert s["dll"]["direct_reference_count"]==1
assert s["dll"]["direct_caller_method_count"]==1
ref=s["dll"]["direct_in_assembly_references"][0]
assert (ref["caller_type"],ref["caller_method"],ref["call_il"],ref["opcode"])==("Weapon","UpdateWeapon","0x009A","call")
sel=s["selection_boundary"]["open_player_man_get_inst"]
assert (sel["token"],sel["code_size"],sel["direct_reference_count"],sel["direct_caller_method_count"])==("0x0600505D",6,171,102)
c=s["capture_boundary"]
assert c["weapon_update_equipped_row_count"]==0
assert c["weapon_update_weapon_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPON UPDATE EQUIPPED SUMMARY: PASS")
