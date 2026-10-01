#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"save_data_story_work_getter.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SAVE_DATA_STORY_WORK_GETTER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005171","0x00314983",39,"dcca7695b47672ce7825fed3223764f312476b6d900da9aa66b929a54916780b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(11,1,1)
assert s["dll"]["exact_flow"]["comparison"]=="StoryWork.storyScenario >= 2"
assert s["dll"]["dependency"]["token"]=="0x06003C24"
assert s["dll"]["fact_0099_bridge"]["call_il"]=="0x0000"
print("DLL SAVE DATA STORY WORK GETTER SUMMARY: PASS")
