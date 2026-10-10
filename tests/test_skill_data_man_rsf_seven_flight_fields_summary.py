#!/usr/bin/env python3
"""FACT-0272 static witness and registry uniqueness check."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_rsf_seven_flight_fields.summary.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
m=w["dll"]["method"];a=w["dll"]["window"];f=a["source_fields"]
assert w["source_ids"]==["DLL-001"] and w["dataset_id"]=="DLL_SKILL_DATA_MAN_RSF_SEVEN_FLIGHT_FIELD_WRITES_V1"
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525F",1735,"09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae")
assert (a["start_il"],a["end_exclusive_il"],a["length_bytes"],a["source_sha256"])==("0x02DE","0x033B",93,"a0a46c5f9c7c9dee803a1828f5dcb7d63b976ecaa5737d53b14333e7a0f3464a")
assert [x["name"] for x in f]==["atkStartDist","flyRangeDist","flyFrm","flyV0","flyStartY","flyEndY","skillType"]
assert [x["relative_input_byte"] for x in f]==list(range(40,47))
assert [len(bytes.fromhex(x["il_hex"])) for x in f]==[13,13,13,13,14,14,13]
assert [x["conversion"] for x in f]==["ldelem.u1"]*4+["ldelem.u1; conv.r4"]*2+["ldelem.u1"]
assert sum(x["fact_id"]=="FACT-0272" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert (ROOT/"canonical/facts/FACT-0272-skill-data-man-rsf-seven-flight-fields.json").exists()
print("SKILL DATA MAN RSF SEVEN FLIGHT FIELDS SUMMARY: PASS")
