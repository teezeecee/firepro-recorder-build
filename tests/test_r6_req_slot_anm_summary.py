#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"req_slot_anm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="R6_REQ_SLOT_ANM_CLOSURE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E70" and m["rva"]=="0x002D9FB8"
assert m["signature_blob_hex"]=="20040111870c020802"
assert m["code_size"]==722 and m["code_sha256"]=="c4c109776883423823725f70612e1a7cd7e61367d7680c206bcc838470cf88ef"
r=s["r6"]
assert r["req_slot_pre"]==r["req_slot_post"]==r["paired"]==717
assert r["traced_parent_counts"]=={"ROOT":419,"FormAnimator.StartOpponentAnm":262,"FormAnimator.StartSlotAnm_Immediately":36}
assert r["direct_child_patterns"]=={"Player.ChangeState":703,"Player.ChangeState -> FormAnimator.ReqBasicAnm":14}
assert r["change_state"]["direct_count"]==717 and r["change_state"]["recorded_raw_argument_counts"]=={"NormalAnm":717}
assert r["raw_argument_totals"]["rev"]=={"False":578,"True":139}
assert r["raw_argument_totals"]["atk_side"]=={"True":455,"False":262}
assert r["weapon_override_observation"]["nested_ReqBasicAnm_count"]==14
assert r["weapon_override_observation"]["nonweapon_calls_with_weaponIdx_nonnegative"]==2
assert r["ordinary_path_observation"]=={"no_nested_ReqBasicAnm_count":703,"POST_SkillSlotID_equals_raw_arg1":703,"weapon_override_POST_SkillSlotID_equals_raw_arg1":0}
w=s["witness_digest"]
assert w["record_count"]==717 and w["byte_count"]==89986
assert w["sha256"]=="788630dfe7eaf98e3dfab73ba07c0e9591f9f9a4b97d842614a2b9327fc69f04"
print("R6 REQ SLOT ANM SUMMARY: PASS")
