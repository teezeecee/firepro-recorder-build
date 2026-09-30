#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"init_animation.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="R6_INIT_ANIMATION_CLOSURE_V1"
assert s["source_ids"]==["DLL-001","CAP-R6-001"]
assert s["dll"]["init_animation"]["token"]=="0x06004E73"
assert s["dll"]["init_animation"]["rva"]=="0x002DA2D8"
assert s["dll"]["init_animation"]["code_size"]==1231
assert s["dll"]["init_animation"]["code_sha256"]=="88f9c7d05b183bd3ca737eaa8a23aa9e7a01547134f0caedbd3f8caa13ace396"
assert s["dll"]["update_animation"]["token"]=="0x06004E7E"
assert s["dll"]["update_animation"]["code_size"]==738
assert s["dll"]["update_animation"]["code_sha256"]=="1e18c732ea0674fae8fdecc0b0d06fc976ec4494df663156925e99c4485b4c00"

r=s["r6"]
assert r["init_animation_pre"]==r["init_animation_post"]==r["paired"]==5288
assert r["direct_child_triplets"]==[
  {"start_anm":1,"start_opponent_anm":0,"start_opponent_anm_m":0,"count":4486},
  {"start_anm":1,"start_opponent_anm":1,"start_opponent_anm_m":0,"count":734},
  {"start_anm":1,"start_opponent_anm":1,"start_opponent_anm_m":1,"count":68},
]
assert sum(x["count"] for x in r["direct_child_triplets"])==5288
assert r["start_anm"]["direct_count"]==5288
assert r["start_anm"]["raw_args"]=={"0":5288}
assert r["start_opponent_anm"]["direct_count"]==802
assert r["start_opponent_anm"]["first_raw_arg_equals_init_parent_target"]==802
assert r["start_opponent_anm"]["nested_request_owner_equals_init_parent_target"]==802
assert r["start_opponent_anm"]["nested_request_counts"]=={"FormAnimator.ReqBasicAnm":585,"FormAnimator.ReqSlotAnm":217}
assert r["start_opponent_anm_m"]["direct_count"]==68
assert r["start_opponent_anm_m"]["third_raw_arg_equals_init_parent_target"]==68
assert r["start_opponent_anm_m"]["nested_request_owner_equals_first_raw_arg"]==68
assert r["start_opponent_anm_m"]["nested_request_counts"]=={"FormAnimator.ReqBasicAnm":68}

w=s["witness_digest"]
assert w["record_count"]==5288
assert w["byte_count"]==159356
assert w["sha256"]=="b93ad305982a99a0771b7f833951d22ded564dd5539aeaaeae764637c7dae440"
assert w["reproducibility_tool"]=="tools/prove_init_animation_closure.py"

print("R6 INIT ANIMATION SUMMARY: PASS")
