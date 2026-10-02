#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_drop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_R6_WEAPON_DROP_V1"
assert s["source_ids"]==["DLL-001","CAP-R6-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AB8","0x00434C48","20040111190c11a85c11a768")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",167,"eac3737037ba8ea767d588f6988426f6fd38567d37400dda6e58cfdc20ccc25e")
assert s["dll"]["inbound_direct_reference"]["canonical_fact"]=="FACT-0193"
assert s["dll"]["inbound_direct_reference"]["direct_reference_count"]==1
helpers={(x["token"],x["name"],x["call_il"]) for x in s["dll"]["open_in_assembly_helpers"]}
assert helpers=={("0x06006AB7","SetPattern","0x0041"),("0x0600497C","Range","0x0030")}
r=s["r6"]
assert r["weapon_drop_execution_count"]==11
assert r["all_parent_method"]=="Player.DropWeapon"
assert r["all_traced_child_count_zero"] is True
assert r["pre_post_weaponIdx_unchanged_count"]==11
assert r["raw_args_counts"]=={"Vector3 | 1 | InRing | Left":8,"Vector3 | 1 | InRing | Right":3}
w=s["witness"]
assert (w["record_count"],w["byte_count"],w["sha256"])==(11,1482,"68958e0d08de846fdf50acf4f9710308c78bdd42a62ad3ef8eabe189dbc7ee7f")
print("DLL/R6 WEAPON DROP SUMMARY: PASS")
