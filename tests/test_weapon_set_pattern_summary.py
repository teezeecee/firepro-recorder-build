#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weapon_set_pattern.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPON_SET_PATTERN_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AB7","0x00434C1A","20010108")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("tiny",44,"9fd8e4c6ea0c03f75b3de3aabfbe56ed4bf2f902ffe76bb13f7f57dee7b2c1b3")
assert m["body_hex"]=="7eeab60004282a00000a391c000000027bd6b6000428c06a0006027bd3b60004036fcd6a00066fad02000a2a"
fields={(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]}
assert fields=={
 ("0x0400B6EA","WeaponMan","inst"),
 ("0x0400B6D6","Weapon","sprRen"),
 ("0x0400B6D3","Weapon","kind")
}
helpers={(x["token"],x["name"],x["code_size"],x["code_sha256"]) for x in s["dll"]["open_in_assembly_helpers"]}
assert helpers=={
 ("0x06006AC0","GetInst",6,"8efdce8690337e223d2f0de688a62b433f4d6515c73fa84c203aadbca4f524fb"),
 ("0x06006ACD","GetWeaponSprite",98,"38d479af573bd1d4c4f72ad8947250d2ef5e4353f720d8c431daa0e3551dfb35")
}
assert s["dll"]["direct_reference_count"]==5
assert s["dll"]["direct_caller_method_count"]==5
assert len(s["dll"]["direct_in_assembly_references"])==5
c=s["capture_boundary"]
assert c["weapon_set_pattern_row_count"]==0
assert c["weapon_drop_execution_count"]==11
assert c["promoted_as_evidence"] is False
print("DLL WEAPON SET PATTERN SUMMARY: PASS")
