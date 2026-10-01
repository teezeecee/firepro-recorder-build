#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_update_scheduler.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_UPDATE_SCHEDULER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050AF","0x00309E9C",160,"1a435c9d3f94c89836c5a175bee66f7a1fb84e4e7a7c8af9197108c533df1004")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(55,3,15)
assert s["dll"]["state_22_path"]["raw_state"]==22
calls=s["dll"]["non_22_path"]["ordered_calls"]
assert [x[0] for x in calls]==["PostProcessAnimation","CallFight","Process_Booing","ReturnWrestlers","ReturnWrestlers_Lumberjack","CheckExplosion","FinishCheck","CheckStartRefereeing","Process_MoveToDestination","Process_Walk","Process_Run","Process_StandPose","CheckMatchEnd","UpdateRefereeAnm"]
assert s["dll"]["non_22_path"]["tail"]=="if disturbedCnt > 0: disturbedCnt = disturbedCnt - 1"
assert [(x["method"],x["call_il"]) for x in s["dll"]["direct_callers"]]==[("Update_EntranceScene","0x0021"),("Update_Match","0x0051")]
print("DLL REFEREE UPDATE SCHEDULER SUMMARY: PASS")
