#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"apply_damage_modifiers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_APPLY_DAMAGE_MODIFIERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x0600494B","0x002AEFFC",132,"224619b3628e2141649f4c24f24196c0d810edf2b2bbfeccd289e0822fb98012")
assert a["parameters"]==[{"sequence":1,"name":"slot","type":"SkillSlotEnum"},{"sequence":2,"name":"sd","type":"SkillData"}]
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x0600494C","0x002AF08C",239,"2a91e3b19f7438eefaf7e3b85aa6f4cfb3c8c8a35ab64fdd1aefb71c2e7456b1")
assert b["parameters"]==[{"sequence":1,"name":"atk_pl_idx","type":"Int32"},{"sequence":2,"name":"def_pl_idx","type":"Int32"}]
assert s["dll"]["skill_slot_modifier"]["mode_cases"][0]["difference_eq_1"]==1.2000000476837158
assert s["dll"]["skill_slot_modifier"]["mode_cases"][1]["difference_eq_1"]==1.100000023841858
hi,lo=s["dll"]["exchange_modifier"]["directional_cases"]; assert hi["condition"]=="local2 >= local3" and lo["condition"]=="local2 < local3"
assert [x["return"] for x in hi["thresholds"]]==[0.25,0.33000001311302185,0.5,0.800000011920929]
assert [x["return"] for x in lo["thresholds"]]==[4.0,3.0,2.0,1.2000000476837158]
assert s["dll"]["apply_damage_bridge"]["exchange_raw_slot_values"]==[24,25]
print("DLL APPLY DAMAGE MODIFIERS SUMMARY: PASS")
