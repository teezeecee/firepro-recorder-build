#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"init_anm_work.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_INIT_ANM_WORK_RESET_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E6C" and m["rva"]=="0x002D9DD8"
assert m["signature_blob_hex"]=="200001" and m["parameters"]==[]
assert m["code_size"]==303 and m["code_sha256"]=="cf51dba42ef7e38fee750ed4a8e5eb449511a11583f6bffbdbec3a9e2802250f"
assert len(s["dll"]["form_animator_initialization"])==14
assert len(s["dll"]["player_initialization"])==15
assert s["dll"]["status3_mask"]=={"il":"0x011A..0x012D","field":"Player.Status3","field_token":"0x04005FBB","operation":"Status3 = Status3 & -9","constant":-9}
assert s["dll"]["control_flow"]=={"branches":0,"calls":0,"terminal_il":"0x012E","terminal_instruction":"ret"}
assert s["dll"]["proven_call_boundaries_from_previous_facts"]==[
 {"caller":"FormAnimator.ReqBasicAnm","caller_token":"0x06004E6F","call_il":"0x0063","fact_id":"FACT-0010"},
 {"caller":"FormAnimator.ReqSlotAnm","caller_token":"0x06004E70","call_il":"0x0165","fact_id":"FACT-0009"}
]
print("DLL INIT ANM WORK SUMMARY: PASS")
