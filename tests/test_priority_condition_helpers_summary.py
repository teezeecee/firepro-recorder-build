#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"priority_condition_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PRIORITY_CONDITION_HELPERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==(
 "0x06004FE9","0x002FA69C",111,"022740847f18e115a477191d3dff827edb956e998dae7496eb1ed591b26ae6eb")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(39,5,1)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==(
 "0x06004F1D","0x002E8263",22,"62f4465a263d518b20434cedb4b42170c20ce2113adfaeb967e19f1ff7b3d204")
assert b["parameters"]==[{"sequence":1,"name":"slot","type":"SkillSlotEnum"}]
assert s["dll"]["is_effective_fall"]["rejected_victory_condition_raw"]==[3,4]
assert s["dll"]["is_effective_fall"]["rejected_zone_raw"]==1
assert s["dll"]["equipment_exist_check"]["internal_bounds_check"] is False
assert [x["il"] for x in s["dll"]["is_lot_bridge"]["calls"]]==["0x00D6","0x011F","0x0168","0x01F9"]
print("DLL PRIORITY CONDITION HELPERS SUMMARY: PASS")
