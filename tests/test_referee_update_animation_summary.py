#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_update_animation.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_UPDATE_ANIMATION_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005097","0x00307E94","200001",415,"5d41c826c5bc4929960746b1b03abdd389b4911c89ec01a48fda0eba6e6c9e4a")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(147,11,4)
assert s["dll"]["pause_gate"]["nonzero_effect"]=="return"
assert s["dll"]["request_init"]["writes"][1]==["CurrentAnmIdx",0]
assert s["dll"]["request_init"]["writes"][2]==["isAnmBoot",1]
assert s["dll"]["request_init"]["writes"][3]==["currentFormIdx",-1]
assert s["dll"]["frame_selection"]["form_index_reset_value"]==-1
assert s["dll"]["frame_selection"]["repeat_condition"]=="returned dispFrm == 0"
assert "if PlDir >= 3: local_x = -local_x" in s["dll"]["frame_selection"]["accepted_record_effects"]
assert s["dll"]["sound_branch"]["nonzero_call"]["fact_id"]=="FACT-0064"
assert s["dll"]["shared_tail"]=="FormDispDuration = FormDispDuration - 1"
assert s["dll"]["fact_0069_bridge"]["call_il"]=="0x00C9"
print("DLL REFEREE UPDATE ANIMATION SUMMARY: PASS")
