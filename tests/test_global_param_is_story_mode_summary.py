#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"global_param_is_story_mode.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_GLOBAL_PARAM_IS_STORY_MODE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06001FC1","0x0011382F","000002")
assert (m["code_size"],m["code_sha256"])==(10,"421cdea7e302135e6671b62354bfa5d99562e3a6547b1d20d6aa9492bfa3fa8d")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,0)
assert s["dll"]["field"]=={"name":"GlobalParam.m_SceneMode","token":"0x04002862","signature_blob_hex":"06119094","type":"SceneMode"}
assert s["dll"]["raw_scene_mode_value"]==11
assert s["dll"]["fact_0117_bridge"]["call_il"]=="0x0058"
print("DLL GLOBAL PARAM IS STORY MODE SUMMARY: PASS")
