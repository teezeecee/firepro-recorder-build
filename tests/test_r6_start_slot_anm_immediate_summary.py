#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"start_slot_anm_immediate.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="R6_START_SLOT_ANM_IMMEDIATE_CLOSURE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E71" and m["rva"]=="0x002DA296"
assert m["signature_blob_hex"]=="20040111870c080208"
assert m["code_size"]==38 and m["code_sha256"]=="091053ea365ad855884dd6f93314dd5e1de23bda1c848c291fd2df4d8776d0b2"
assert [x["name"] for x in m["parameters"]]==["skill_slot","anm_bank","rev","def_pl_idx"]
r=s["r6"]
assert r["start_slot_pre"]==r["start_slot_post"]==r["paired"]==36
assert r["traced_parent_counts"]=={"Player.PostprocessEachState":32,"ROOT":4}
assert r["direct_child_sequence"]=={"FormAnimator.ReqSlotAnm -> FormAnimator.StartAnm":36}
assert all(v==36 for v in r["parent_argument_relations"].values())
assert r["resolved_skill_relations"]["ReqSlotAnm_POST_ResolvedSkillSource_counts"]=={"ReqSlotAnm.owner_slot":36}
assert r["parent_arg1_counts"]=={"ExchangeOfStriking":32,"ExchangeOfStriking_Performance":2,"ExchangeOfStriking_Finish":2}
assert r["parent_arg2_counts"]=={"4":26,"0":4,"8":4,"2":2}
assert r["parent_arg3_counts"]=={"True":36}
w=s["witness_digest"]
assert w["record_count"]==36 and w["byte_count"]==4822
assert w["sha256"]=="deafacce031d382aacfde3a1fdb8c7f03bd1bcc8559a70156d613a0d23c6a9a5"
print("R6 START SLOT ANM IMMEDIATE SUMMARY: PASS")
