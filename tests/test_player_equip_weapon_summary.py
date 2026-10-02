#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_equip_weapon.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_R6_PLAYER_EQUIP_WEAPON_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06004EE0","0x002E1AB0","20010108")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",91,"f4436e9f21bb7d3b9eef160a5967c34e25eeaf52fcfcc87d41f6524ececa61eb")
assert s["dll"]["calls"]["get_weapon_obj"]["token"]=="0x06006AC8"
assert s["dll"]["calls"]["get_weapon_obj"]["canonical_status"]=="OPEN_SEPARATE_GATE"
assert s["dll"]["fact0015_bridge"]["call_il"]=="0x00E9"
r=s["r6"]
assert r["equip_weapon_execution_count"]==11
assert all(v==11 for v in r["relations"].values())
d=s["witness_digest"]
assert (d["record_count"],d["byte_count"],d["sha256"])==(11,794,"ee0f5723f7ae37c9742c154b75dd9055dc2b04cf84e8c9b60b76f82801fde1bf")
print("DLL/R6 PLAYER EQUIP WEAPON SUMMARY: PASS")
