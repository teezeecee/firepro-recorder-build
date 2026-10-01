#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_call_fight.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_CALL_FIGHT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005080","0x00306394",100,"fba8e1eb077d2800274abf6f40345ed6768347f753aedaf9ccb023b2a24ea530")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(35,4,2)
assert s["dll"]["gates"][0]["condition"]=="State == raw 19"
assert s["dll"]["gates"][2]["expression"]=="currentFormIdx == anmData[CurrentAnmIdx].formNum - 6 - 1"
assert [(x["method"],x["raw_argument"]) for x in s["dll"]["success_calls"]]==[("PlayRefereeVoice",0),("Show_Fight",1)]
assert s["dll"]["fact_0074_bridge"]["call_il"]=="0x002D"
print("DLL REFEREE CALL FIGHT SUMMARY: PASS")
