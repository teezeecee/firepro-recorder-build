#!/usr/bin/env python3
"""FACT-0267 summary and registry uniqueness checks."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_packed_nibbles.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
m=w["dll"]["method"];c=w["dll"]["cursor"];fld=w["dll"]["fields"];flag=w["dll"]["flag_path"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_PACKED_NIBBLES_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["code_bytes"],m["code_sha256"])==("0x0600525F","0x0031F694",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert c["initial_skip_count"]==10 and c["initial_increment_hex"]=="0817580c"
assert [x["name"] for x in fld]==["winningTechDispType","artPoint","cheerLevel","cheerType"]
assert [x["byte_offset"] for x in fld]==[14,14,15,15]
assert [x["token"] for x in fld]==["0x04007C72","0x04007C73","0x04007C74","0x04007C75"]
assert [x["source_slice_il"] for x in fld]==["0x007B","0x0086","0x009C","0x00A7"]
assert (flag["mask"],flag["bit_set"],flag["branch_target_il"])==(128,256,"0x00D2")
assert sum(x["fact_id"]=="FACT-0267" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (R/"canonical/facts/FACT-0267-skill-data-man-rsf-packed-nibbles.json").exists()
print("SKILL DATA MAN RSF PACKED NIBBLES SUMMARY: PASS")
