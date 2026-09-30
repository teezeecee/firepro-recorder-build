#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"start_opponent_anm_m.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="R6_START_OPPONENT_ANM_M_CLOSURE_V1"
m=s["dll"]["start_opponent_anm_m"]
assert m["token"]=="0x06004E77"
assert m["rva"]=="0x002DAF40"
assert m["signature_blob_hex"]=="200301080808"
assert m["parameters"]==[
    {"sequence":1,"name":"en","element_type":"I4"},
    {"sequence":2,"name":"anm_idx","element_type":"I4"},
    {"sequence":3,"name":"mp","element_type":"I4"},
]
assert m["code_size"]==462
assert m["code_sha256"]=="e4d47db13c895255bbbd2d9d112427c93491b757a4bde1ee9543265724e1b566"
assert m["request_dispatch"]["call_token"]=="0x06004E6F"
assert m["terminal_call"]["token"]=="0x06004EDF"

r=s["r6"]
assert r["start_opponent_anm_m_pre"]==r["start_opponent_anm_m_post"]==r["paired"]==68
assert r["traced_parent_counts"]=={"FormAnimator.InitAnimation":68}
assert r["direct_child_pattern"]=={"FormAnimator.ReqBasicAnm":68,"Player.DropWeapon":68}
assert r["argument_relations"]=={
    "second_raw_argument_equals_2":68,
    "third_raw_argument_equals_parent_InitAnimation_target":68,
    "first_raw_argument_equals_nested_ReqBasicAnm_owner_slot":68,
    "first_raw_argument_equals_direct_DropWeapon_owner_slot":68,
    "host_owner_arg1_arg3_pairwise_distinct":68,
}
assert r["nested_req_basic"]["exactly_one_per_parent"]==68
assert r["nested_req_basic"]["raw_args_equal_parent_BasicSkillID_false_minus1"]==68
assert r["nested_req_basic"]["recorded_target_equals_arg3"]==54
assert r["nested_req_basic"]["recorded_target_differs_from_arg3"]==14
assert r["post_assignment_snapshot_at_drop_weapon"]["recorded_AnmHostPlayer_equals_StartOpponentAnmM_owner_slot"]==68
assert r["post_assignment_snapshot_at_drop_weapon"]["nested_ReqBasicAnm_POST_to_DropWeapon_PRE_AnmHostPlayer_changed"]==48

w=s["witness_digest"]
assert w["record_count"]==68
assert w["byte_count"]==4259
assert w["sha256"]=="2c61df5bd859ed15755a4929bd3f403691667423ee33bb4d8520e86e12153713"
assert w["reproducibility_tool"]=="tools/prove_start_opponent_anm_m_closure.py"

print("R6 START OPPONENT ANM M SUMMARY: PASS")
