#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"apply_damage.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_APPLY_DAMAGE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x0600494D" and m["rva"]=="0x002AF188"
assert m["signature_blob_hex"]=="0002010808"
assert m["parameters"]==[{"sequence":1,"name":"atk_pl_idx","type":"Int32"},{"sequence":2,"name":"def_pl_idx","type":"Int32"}]
assert m["code_size"]==1641 and m["code_sha256"]=="6ecc8c9b5e71235fcbde51d1ca3d8baafd5b4d713abc298947b6848627d419b5"
assert m["instruction_count"]==569 and m["branch_instruction_count"]==55 and m["call_instruction_count"]==40
assert s["dll"]["modifier_setup"][1]["raw_slot_values"]==[24,25]
assert s["dll"]["critical_split"]["critical_check_token"]=="0x06004949"
assert [x["calc_il"] for x in s["dll"]["ordinary_branch"]["paths"]]==["0x01E8","0x029A","0x02B9","0x02FD","0x0341","0x0385","0x03C9"]
assert [x["final_call"] for x in s["dll"]["ordinary_branch"]["paths"]]==["Player.AddHP","Player.AddBP","Player.AddHP_Neck","Player.AddHP_Arm","Player.AddHP_Waist","Player.AddHP_Leg","Player.AddSP"]
assert s["dll"]["update_animation_bridge"]=={"fact_id":"FACT-0014","caller":"FormAnimator.UpdateAnimation","caller_token":"0x06004E7E","call_il":"0x025F","callee_token":"0x0600494D","arguments":"plObj.PlIdx, plObj.TargetPlIdx","raw_form_flag_mask":32}
assert s["dll"]["converged_tail"]["return_il"]=="0x0668"
print("DLL APPLY DAMAGE SUMMARY: PASS")
