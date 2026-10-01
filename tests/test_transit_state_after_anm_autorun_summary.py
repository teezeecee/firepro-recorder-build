#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"transit_state_after_anm_autorun.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_TRANSIT_STATE_AFTER_ANM_AUTORUN_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06004EC7","0x002E08B8",712,"6bd624830f79c47cf800b28715a0f2628127003f9bf80484b8da7793ecaeb56d")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(227,32,19)
assert s["dll"]["geometry_gate"]["skip_to_final_when"]==["venue.ringKind == 1","venue.ringKind == 3","Zone != 0"]
assert s["dll"]["distance_and_parity"]["raw_thresholds"]==[2.0833332538604736,2.9166665077209473]
assert s["dll"]["true_tail"][0]=="ChangeState(56)"
assert "target.ChangeState(47)" in s["dll"]["false_tail"]
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0048" and s["dll"]["caller_bridge"]["raw_anime_end"]==9
print("DLL TRANSIT STATE AFTER ANM AUTORUN SUMMARY: PASS")
