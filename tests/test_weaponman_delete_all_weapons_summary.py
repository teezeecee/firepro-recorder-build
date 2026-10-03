#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_delete_all_weapons.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_DELETE_ALL_WEAPONS_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AC7","0x004353DC","200001")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",26,"3e9811a875cf2dd7f62779e8ecf7cedaaf32084fcdeec863aa8e829aaa3c6467")
assert m["body_hex"]=="160a380b000000020628c66a00060617580a061e3feeffffff2a"
calls=s["dll"]["internal_game_method_calls"]
assert len(calls)==1
assert (calls[0]["token"],calls[0]["owner"],calls[0]["method"],calls[0]["call_il"],calls[0]["canonical_fact"])==("0x06006AC6","WeaponMan","DeleteWeapon","0x0009","FACT-0199")
assert s["dll"]["direct_reference_count"]==3
assert s["dll"]["direct_caller_method_count"]==3
refs={(x["caller_type"],x["caller_method"],x["call_il"],x["opcode"]) for x in s["dll"]["direct_in_assembly_references"]}
assert refs=={
 ("MatchMain","ProceedNextRound","0x0091","callvirt"),
 ("MatchMain","Update","0x0463","callvirt"),
 ("MatchMainCp","Update","0x02B1","callvirt")
}
c=s["capture_boundary"]
assert c["weaponman_delete_all_weapons_row_count"]==0
assert c["matchmain_proceed_next_round_row_count"]==0
assert c["matchmain_update_row_count"]==0
assert c["matchmaincp_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL WEAPONMAN DELETE ALL WEAPONS SUMMARY: PASS")
