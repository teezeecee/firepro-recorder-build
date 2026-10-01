#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"story_save_data_manager_get_story_data_scenario.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_STORY_SAVE_DATA_MANAGER_GET_STORY_DATA_SCENARIO_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06003C25","0x0023A1CA","2001129cd4119cd0")
assert (m["code_size"],m["code_sha256"])==(29,"bddbc1bb012966f7b1473c87204f7669e637de70bbb3ab6069be5d1e5cb79861")
assert m["parameters"]==[{"sequence":1,"type":"StoryScenario"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(13,1,0)
assert s["dll"]["exact_flow"]["raw_value"]==2
assert s["dll"]["fields"]["save_data_inst"]["token"]=="0x040064EC"
assert s["dll"]["fields"]["save_data_array"]["token"]=="0x0400650F"
assert s["dll"]["fields"]["manager_array"]["token"]=="0x04004980"
assert s["dll"]["fact_0103_bridge"]["call_il"]=="0x0006"
print("DLL STORY SAVE DATA MANAGER GET STORY DATA SCENARIO SUMMARY: PASS")
