#!/usr/bin/env python3
"""FACT-0276 static RSF entry field witness, offsets and unique registry."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
m=w["dll"]["method"];a=w["dll"]["window"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_ANM_ENTRY_FIELDS_AND_CURSOR_GAP_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x03CC","0x0470",164,"7e28036b4af6f3232e543e9c4fb681e389a9cab6b52aede3a95f9d85731620a9")
assert [len(bytes.fromhex(x["il_hex"])) for x in a["segments"]]==[8,9,9,98,12,28]
assert sum(len(bytes.fromhex(x["il_hex"])) for x in a["segments"])==164
assert len(a["fields"])==12
assert [x["name"] for x in a["fields"]]==["atkColAng","atkColPos","atkColSize","formNum","loopReturnPoint","loopReturnTo","fallTiming","terrainColType","hitSE","cheerLevel","anmStartState","anmEndState"]
assert [x["source"] for x in a["fields"]]==["local3","local7","local10",64,65,66,67,68,69,70,74,75]
assert a["source_byte_offsets_read"]==[64,65,66,67,68,69,70,74,75]
assert a["cursor_positions_skipped_without_read"]==[71,72,73]
assert a["segments"][4]["il_hex"]=="0817580c"*3
assert len({x["token"] for x in a["fields"]})==12
assert sum(x["fact_id"]=="FACT-0276" for x in r["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
assert (ROOT/"canonical/facts/FACT-0276-skill-data-man-rsf-anm-entry-fields-cursor-gap.json").exists()
print("SKILL DATA MAN RSF ANM ENTRY FIELD CURSOR GAP SUMMARY: PASS")
