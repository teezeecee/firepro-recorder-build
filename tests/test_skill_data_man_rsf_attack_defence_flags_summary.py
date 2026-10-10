#!/usr/bin/env python3
"""FACT-0269 witness/registry structural test; source replay is separate."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_attack_defence_flags.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
d=w["dll"];c=d["source_window"];fs=d["original_fields"];tests=d["bit_tests"]
assert w["source_ids"]==["DLL-001"] and w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ATTACK_DEFENCE_PARAM_FLAGS_V1"
assert (d["method"]["token"],d["method"]["code_size"],d["method"]["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (c["begin_il"],c["end_exclusive_il"],c["byte_count"],c["sha256"])==("0x017F","0x023C",189,"a5a334f393cc1a57fb99052c3dc9d5c980fad164a7cd51741c5f7b511f41a7fb")
assert [x["name"] for x in fs]==["atkPrmType_Main","atkPrmType_Sub","defPrmType_Main","defPrmType_Sub"]
assert [x["relative_input_byte"] for x in fs]==[26,26,27,27]
assert [x["mask"] for x in tests]==[1,2,4,8]
assert [x["or_bit"] for x in tests]==[512,1024,2048,4096]
assert [x["skip_to_il"] for x in tests]==["0x01EB","0x0206","0x0221","0x023C"]
assert sum(x["fact_id"]=="FACT-0269" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (R/"canonical/facts/FACT-0269-skill-data-man-rsf-attack-defence-flags.json").exists()
print("SKILL DATA MAN RSF ATTACK DEFENCE FLAGS SUMMARY: PASS")
