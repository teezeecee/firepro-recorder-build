#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_get_weapon_obj.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WEAPONMAN_GET_WEAPON_OBJ_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AC8","0x00435402","200112b50808")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("tiny",25,"e14e6ddd19807cae5dc1385638f47047f66403daae447e5cdaaa53a82253a0ee")
assert m["body_hex"]=="03163f07000000031e3f02000000142a027becb60004039a2a"
f=s["dll"]["field"]
assert (f["token"],f["signature_blob_hex"],f["type"])==("0x0400B6EC","061d12b508","Weapon[]")
refs=s["dll"]["direct_in_assembly_references"]
assert len(refs)==9
pairs={(x["caller_token"],x["call_il"]) for x in refs}
assert ("0x06004E70","0x00FD") in pairs
assert ("0x06004EE0","0x0013") in pairs
assert s["capture_boundary"]["promoted_as_evidence"] is False
print("DLL WEAPONMAN GET WEAPON OBJ SUMMARY: PASS")
