#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"ai_update_player.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_UPDATE_PLAYER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x06004F87","0x002F4308",836,"da9fecfe8759295bfca091cebf9c3d58f54802008907127c9658db73eadfbf15")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(268,26,38)
assert s["dll"]["status2_mask64"]=={"raw_mask":64,"change_state_argument":10,"request":"animator.ReqBasicAnm(animator.WazaRequest, true, TargetPlIdx)","clear_mask":-65}
assert s["dll"]["standing_state_region"]["condition"]=="signed State <= 4"
assert s["dll"]["tail"]["rebound_keep_states"]==[5,32]
assert s["dll"]["tail"]["requested_force_control_states"]==[0,1,2,3,6]
calls=s["dll"]["ordered_calls"]
assert len(calls)==38
assert calls[1]=={"il":"0x0034","method":"PlayerController_AI.CalcTouchTime","token":"0x06004FFE"}
assert calls[-1]=={"il":"0x033E","method":"Player.ProcessBloodstain","token":"0x06004F80"}
assert [x["call_il"] for x in s["dll"]["caller_bridges"]]==["0x00CC","0x026F"]
print("DLL AI UPDATE PLAYER SUMMARY: PASS")
