#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"play_animation_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_R6_PLAY_ANIMATION_SE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E7D" and m["rva"]=="0x002DB718"
assert m["code_size"]==364 and m["code_sha256"]=="ba7c6da321b3f5632756459a8a788abd92609da056981078f5fc7bbe04824085"
assert len(s["dll"]["dispatch"]["numeric_cases"])==6
assert len(s["dll"]["exact_call_sites"])==14
assert s["dll"]["update_animation_bridge"]["fact_id"]=="FACT-0014"
r=s["r6"]
assert r["play_animation_se_pre"]==r["play_animation_se_post"]==r["paired"]==45458
assert r["traced_parent_counts"]=={"ROOT":45458}
assert r["direct_child_patterns"]=={"no traced child":45447,"Player.EquipWeapon":11}
e=r["equip_weapon_branch_observation"]
assert e["count"]==11
assert e["parent_PRE_weaponIdx_minus1"]==e["child_PRE_weaponIdx_minus1"]==11
assert e["child_owner_slot_equals_parent_owner_slot"]==11
assert e["child_raw_arg_equals_child_POST_weaponIdx"]==11
assert e["parent_POST_weaponIdx_equals_child_raw_arg"]==11
w=s["witness_digest"]
assert w["record_count"]==45458 and w["byte_count"]==4314316
assert w["sha256"]=="269d9efa1f0bb19e53a398b53c395033084ddc30b8ea6718514911e45697f692"
print("PLAY ANIMATION SE SUMMARY: PASS")
