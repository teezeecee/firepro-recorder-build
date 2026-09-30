#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"start_anm.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="R6_START_ANM_CLOSURE_V1"
m=s["dll"]["start_anm"]
assert m["token"]=="0x06004E75"
assert m["rva"]=="0x002DAA54"
assert m["signature_blob_hex"]=="20010108"
assert m["parameter"]=={"sequence":1,"name":"anm_idx","element_type":"I4"}
assert m["code_size"]==328
assert m["code_sha256"]=="aa80c075f247570daf6d74d8d5d7140022160f98a0d3b6233cd7268236a69c94"
assert m["terminal_call"]=={"il_offset":"0x0142","method":"FormAnimator.PreprocessEachAnm","token":"0x06004E78"}

b=s["dll"]["start_slot_anm_immediately_bridge"]
assert b["token"]=="0x06004E71"
assert b["code_size"]==38
assert b["code_sha256"]=="091053ea365ad855884dd6f93314dd5e1de23bda1c848c291fd2df4d8776d0b2"
assert b["start_anm_call"]["argument_instruction"]=="ldarg.2"
assert b["start_anm_call"]["target_token"]=="0x06004E75"

r=s["r6"]
assert r["start_anm_pre"]==r["start_anm_post"]==r["paired"]==5333
assert r["traced_parent_counts"]=={
    "FormAnimator.InitAnimation":5288,
    "FormAnimator.StartSlotAnm_Immediately":36,
    "ROOT":9,
}
assert r["raw_argument_counts"]=={"0":5292,"4":26,"1":9,"8":4,"2":2}
assert r["raw_argument_counts_by_traced_parent"]=={
    "FormAnimator.InitAnimation":{"0":5288},
    "FormAnimator.StartSlotAnm_Immediately":{"4":26,"8":4,"2":2,"0":4},
    "ROOT":{"1":9},
}
assert r["recorded_host_field"]=={
    "pre_AnmHostPlayer_equals_owner_slot":5089,
    "post_AnmHostPlayer_equals_owner_slot":5333,
    "pre_to_post_AnmHostPlayer_changed":244,
}
assert r["start_slot_bridge"]=={
    "observed_parent_child_pairs":36,
    "parent_second_raw_argument_equals_child_StartAnm_raw_argument":36,
}
assert r["traced_direct_children"]=={"Player.ChangeState":2}

w=s["witness_digest"]
assert w["record_count"]==5333
assert w["byte_count"]==307108
assert w["sha256"]=="bdc1ebb858f74602c3c364ce5ca695f7663380703770237421e50e872783f048"
assert w["reproducibility_tool"]=="tools/prove_start_anm_closure.py"

print("R6 START ANM SUMMARY: PASS")
