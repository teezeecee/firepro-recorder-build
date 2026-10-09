#!/usr/bin/env python3
"""FACT-0268 source fixture, registry uniqueness and branch geometry."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_attack_byte_run.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"];f=d["field_writes"];t=d["split"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ATTACK_BYTE_RUN_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600525F","0x0031F694",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert [x["read_input_relative_offset"] for x in f]==list(range(16,25))
assert [int(x["il_offset"],16) for x in f]==[0xD2+13*i for i in range(9)]
assert [x["name"] for x in f]==["anmType","comboAnmPosMdf","atkPow_HP","atkPow_SP","atkPow_Neck","atkPow_Arm","atkPow_Waist","atkPow_Leg","atkPow_BP"]
assert all(len(bytes.fromhex(x["il_body_hex"]))==13 and x["il_body_hex"].startswith("0703082517580c917d") for x in f)
assert (t["raw_input_relative_offset"],t["signed_compare_literal"],t["bge_il"],t["bge_target"],t["br_il"],t["br_target"])==(25,50,"0x0154","0x016D","0x0168","0x017F")
assert len(bytes.fromhex(t["exact_source_hex"]))==0x17f-0x147
assert [x["name"] for x in t["fields"]]==["bleedingRate","anmLoopTimes"]
assert t["below_threshold"]=={"bleedingRate":"raw byte25","anmLoopTimes":0}
assert t["at_or_above_threshold"]=={"bleedingRate":0,"anmLoopTimes":"raw byte25 - 50"}
assert sum(x["fact_id"]=="FACT-0268" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (R/"canonical/facts/FACT-0268-skill-data-man-rsf-attack-byte-run.json").exists()
print("SKILL DATA MAN RSF ATTACK BYTE RUN SUMMARY: PASS")
