#!/usr/bin/env python3
"""FACT-0270 static witness and registry one-to-one regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_six_suicide_damage_bytes.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"];win=d["window"];f=win["six_13_byte_field_reads"]
assert w["source_ids"]==["DLL-001"] and w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SIX_SUICIDE_DAMAGE_BYTES_AND_FLAGS_V1"
assert (m["token"],m["rva"],m["il_bytes"],m["il_sha256"])==("0x0600525F","0x0031F694",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (win["start_il"],win["end_exclusive_il"],win["byte_count"],win["sha256"])==("0x023C","0x029E",98,"b3fc6e13734c07833e950e4566966ea0cb8db24263a036892e258399411bfe68")
assert [x["relative_input_offset"] for x in f]==[29,30,31,32,33,34]
assert [x["source_il"] for x in f]==["0x023C","0x0249","0x0256","0x0263","0x0270","0x027D"]
assert [x["name"] for x in f]==["suicideDamage_HP","suicideDamage_SP","suicideDamage_Neck","suicideDamage_Arm","suicideDamage_Waist","suicideDamage_Leg"]
assert [x["token"] for x in f]==["0x04007C65","0x04007C66","0x04007C67","0x04007C68","0x04007C69","0x04007C6A"]
assert all(len(bytes.fromhex(x["source_hex"]))==13 for x in f)
assert (win["flags_read"]["il"],win["flags_read"]["relative_input_offset"],win["flags_read"]["flags_field_token"])==("0x028A",35,"0x04007C55")
assert len(bytes.fromhex(win["flags_read"]["source_hex"]))==20
assert sum(x["fact_id"]=="FACT-0270" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (R/"canonical/facts/FACT-0270-skill-data-man-rsf-six-suicide-damage-bytes.json").exists()
print("SKILL DATA MAN RSF SIX SUICIDE DAMAGE BYTES SUMMARY: PASS")
