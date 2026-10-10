#!/usr/bin/env python3
"""FACT-0273 static-only source witness and registry identity."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_hit_damage_nibbles.summary.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
a=w["dll"]["window"];s=a["source_segments"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_HIT_DAMAGE_NIBBLES_AND_ROPE_CONSTANT_V1" and w["source_ids"]==["DLL-001"]
assert w["dll"]["method"]["code_sha256"]=="09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae"
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x033B","0x0361",38,"aa4a812064ef0103aa51f60f82ebfbbbb1f15b4351ece9a39dfbbc72159b55ee")
assert a["relative_input_byte"]==47 and a["postincrement_old_cursor"] and a["no_branches_within_window"]
assert [x["name"] for x in s]==["read_byte_to_local4","hitDmgType_Single","hitDmgType_Combo","ropeEscapeDir"]
assert [len(bytes.fromhex(x["il_hex"])) for x in s]==[9,11,10,8]
assert "".join(x["il_hex"] for x in s)=="03082517580c9113040711041f0f5f7d587c00040711041a637d597c0004071f0f7d767c0004"
assert [x["token"] for x in s[1:]]==["0x04007C58","0x04007C59","0x04007C76"]
assert s[1]["operation"]=="field = local4 & 15" and s[2]["operation"]=="field = local4 shr.un 4"
assert "ldc.i4.s 15" in s[3]["operation"]
assert sum(x["fact_id"]=="FACT-0273" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (ROOT/"canonical/facts/FACT-0273-skill-data-man-rsf-hit-damage-nibbles.json").exists()
print("SKILL DATA MAN RSF HIT DAMAGE NIBBLES SUMMARY: PASS")
