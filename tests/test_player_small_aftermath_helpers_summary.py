#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_small_aftermath_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_SMALL_AFTERMATH_HELPERS_V1"
ms={m["name"]:m for m in s["dll"]["methods"]}
exp={
"SetLastDamage":("0x06004EDC","0x002E197E",8,"aa8386105dc125796e2f61ab7fabade30391f80863d7231c8dce82017bc25826"),
"SetLastSkill":("0x06004EB1","0x002DE4CF",26,"743d99df562a3f16f12fd7da264fa22386474eec9f6eee8061d83c0c690fb959"),
"Bleeding":("0x06004F1F","0x002E828C",50,"2a308caf2b1dd0cb7166f4123e2a23ef24d8c3088294ddefea0f41384991c4a6"),
"SetDownTime":("0x06004ED8","0x002E18A0",64,"670ac32434c8e7ed6e8fea9b78f446e73ec1a0c0c58756add4cb55f6ed6a73c2")}
for n,e in exp.items(): assert (ms[n]["token"],ms[n]["rva"],ms[n]["code_size"],ms[n]["code_sha256"])==e
assert s["dll"]["set_last_damage"]["last_damage_field_token"]=="0x04005FD1"
assert s["dll"]["set_last_skill"]["reset_checked_pri_act_token"]=="0x06005007"
assert s["dll"]["bleeding"]["bled_count_field_token"]=="0x040056D7"
assert s["dll"]["set_down_time"]["clamp_continue_opcode"]=="bge" and s["dll"]["set_down_time"]["raw_min"]==0
assert [x["fact_id"] for x in s["dll"]["caller_bridges"]]==["FACT-0020","FACT-0021","FACT-0026"]
print("DLL PLAYER SMALL AFTERMATH HELPERS SUMMARY: PASS")
