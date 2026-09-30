#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"req_basic_anm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="R6_REQ_BASIC_ANM_CLOSURE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E6F" and m["rva"]=="0x002D9F40"
assert m["signature_blob_hex"]=="20030111a9700208"
assert [x["name"] for x in m["parameters"]]==["basic_skill_id","rev","def_pl_idx"]
assert m["code_size"]==105 and m["code_sha256"]=="fe75cf6bc4bc9f8915c55ace5e83feb79f2e1cf78577756b04bd7f8843d36f16"
r=s["r6"]
assert r["req_basic_pre"]==r["req_basic_post"]==r["paired"]==5761
assert r["direct_traced_children"]==0
assert r["traced_parent_counts"]=={"ROOT":4391,"Player.TransitStateAfterAnm":590,"FormAnimator.StartOpponentAnm":585,"Player.PostprocessEachState":113,"FormAnimator.StartOpponentAnmM":68,"FormAnimator.ReqSlotAnm":14}
assert r["raw_argument_relations"]=={"rev_false_and_def_pl_idx_minus1":5714,"rev_true_and_def_pl_idx_equals_recorded_target":47,"all_rev_true_calls_traced_as_ROOT":47,"distinct_basic_skill_id_strings":168,"distinct_full_argument_tuples":201}
assert r["basic_skill_field_observation"]=={"POST_BasicSkillID_equals_raw_arg1":5761,"PRE_BasicSkillID_already_equals_raw_arg1":167,"PRE_to_POST_BasicSkillID_changed":5594}
assert r["known_parent_bridges"]["StartOpponentAnm"]["child_arg1_equals_parent_BasicSkillID"]==585
assert r["known_parent_bridges"]["StartOpponentAnmM"]["child_arg1_equals_parent_BasicSkillID"]==68
assert r["known_parent_bridges"]["ReqSlotAnm_weapon_override"]["count"]==14
w=s["witness_digest"]
assert w["record_count"]==5761 and w["byte_count"]==482616
assert w["sha256"]=="08e17ff201a4a670a28ea44cf44e1200cacb0659f4eb455a918ce1a13fb56d4f"
print("R6 REQ BASIC ANM SUMMARY: PASS")
