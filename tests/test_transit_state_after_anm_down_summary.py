#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"transit_state_after_anm_down.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_TRANSIT_STATE_AFTER_ANM_DOWN_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06004EC6","0x002E0584",807,"279517cb863c131495de999594e2eecb0ec3cfaada975d4215ee0efd7fb2b6f6")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(265,24,25)
sel=s["dll"]["non_ko_selection"]
assert [(x["field"],x["superpain_bit"],x["raw_animation"]) for x in sel]==[
 ("HP_Neck",1,354),("HP_Arm",2,356),("HP_Waist",4,358),("HP_Leg",8,360)]
assert s["dll"]["non_ko_default_animation"]==180
assert s["dll"]["ko_path"]["form_100"]=={"raw_animation":296,"change_state":17}
assert s["dll"]["mine_tail"]["conditions"]==["venue.ringKind == 4","Ring.IsStepOnMine(PlIdx) == true"]
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0048"
print("DLL TRANSIT STATE AFTER ANM DOWN SUMMARY: PASS")
