#!/usr/bin/env python3
"""FACT-0265 summary check; retail-byte verification is separate."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_data_man_packed_skill_loop.summary.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
m=w["dll"]["method"]
assert w["dataset_id"]=="DLL_SKILL_DATA_MAN_PACKED_SKILL_LOOP_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["code_size"],m["instructions"],m["branches"])==("0x06005257","0x0031F290",354,148,16)
assert m["code_sha256"]=="9a502219cf3c64f9b5971f6b3ccaa74b719c1f5477c61a980806bc6e2d4f0545"
assert [(v["il"],v["value"]) for v in w["dll"]["constants"]]==[("0x0042",2675),("0x007C",2675),("0x00B0",4188),("0x0157",2000)]
assert len(w["dll"]["methoddef_children"])==6 and w["dll"]["direct_caller"]["il"]=="0x001F"
assert (R/"canonical/facts/FACT-0265-skill-data-man-packed-skill-loop.json").exists()
assert sum(x["fact_id"]=="FACT-0265" for x in reg["families"])==1
assert sum(x["family_id"]==w["dataset_id"] for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("SKILL DATA MAN PACKED SKILL LOOP SUMMARY: PASS")
