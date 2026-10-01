#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_process_match_end_normal.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_PROCESS_MATCH_END_NORMAL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050A7","0x00309428",156,"e71d1708191a0dc125367efbaa8adb8c280f8e1068cf6ae26ea320a98d482d8b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(56,9,8)
assert s["dll"]["scan"]["selected_index_initial"]==-1
assert s["dll"]["scan"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":7}
assert [x["token"] for x in s["dll"]["selected_flow"]]==["0x06004924","0x060047D8","0x060047DA","0x060047D9","0x06004928"]
assert s["dll"]["selected_flow"][2]["arguments"]==[4,True]
assert s["dll"]["selected_flow"][3]["arguments"]==[6,4]
assert s["dll"]["direct_callers"]==[{"fact_id":"FACT-0091","type":"Referee","method":"CheckMatchEnd","token":"0x060050A9","rva":"0x00309544","call_il":"0x00A2","opcode":"call"}]
print("DLL REFEREE PROCESS MATCH END NORMAL SUMMARY: PASS")
