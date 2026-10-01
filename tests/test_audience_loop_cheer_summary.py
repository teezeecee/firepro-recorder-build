#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audience_loop_cheer.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIENCE_LOOP_CHEER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060047DA","0x0028FF68",276,"45701fac9b7e62ecbae949718859ea29a3dac586af0f7494c87b405de7262b4b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(107,12,5)
assert s["dll"]["nlevel_clamp"]=={"min":1,"max":4}
assert [x["raw_id"] for x in s["dll"]["raw_id_selection"]]==[39,40,41]
assert s["dll"]["volume_flow"]["zero_test"]["opcode"]=="bne.un"
assert s["dll"]["dispatch"]["start_or_replace"]["call"]["token"]=="0x060052AD"
assert s["dll"]["dispatch"]["volume_only"]["call"]["token"]=="0x060052B0"
assert s["dll"]["fact_0079_bridge"]["raw_arguments"]==[0,False]
print("DLL AUDIENCE LOOP CHEER SUMMARY: PASS")
