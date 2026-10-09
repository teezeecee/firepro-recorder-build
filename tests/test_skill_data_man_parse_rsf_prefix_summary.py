#!/usr/bin/env python3
"""FACT-0266 source witness; raw source is verified separately."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_parse_rsf_prefix.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
assert w["source_ids"]==["DLL-001"] and w["dataset_id"]=="DLL_SKILL_DATA_MAN_PARSE_RSF_PREFIX_V1"
m=w["parser"];e=w["quarantined_export_observation"]
assert (m["code_bytes"],m["instruction_count"],m["rva"])==(1735,971,"0x0031F694")
assert m["code_sha256"]=="09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae"
assert [x["relative_offset"] for x in m["byte_field_sites"]]==[10,11]
assert [x["field"] for x in m["byte_field_sites"]]==["reversalSkillType","reversalRateType"]
assert len(bytes.fromhex(m["cursor_skip_hex"]))==42 and len(bytes.fromhex(m["entry_hex"]))==27
assert m["cursor_derivation"]["initial_advances"]==10 and m["cursor_derivation"]["advance_repeat_count"]==10
assert m["cursor_derivation"]["advance_pattern_hex"]=="0817580c"
assert m["cursor_derivation"]["read_pattern_hex"]=="03082517580c91"
assert e["script_length"]==e["first_offset_ge_length_value"]==1511028 and e["first_offset_ge_length_index"]==3875
assert e["index_pair_count"]==3876 and e["populated_before_stop"]==3054 and e["zero_length_before_stop"]==821
assert e["source_status"]=="PARENT_UNVERIFIED_NONCANONICAL"
assert sum(x["fact_id"]=="FACT-0266" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (R/"canonical/facts/FACT-0266-skill-data-man-parse-rsf-prefix.json").exists()
print("SKILL DATA MAN PARSE RSF PREFIX SUMMARY: PASS")
