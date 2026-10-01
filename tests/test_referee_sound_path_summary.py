#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_sound_path.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_SOUND_PATH_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x06004971","0x002B0B50",87,"1875e52cbc086e1797f248a8f89340c75605d756409b3eb4e4bf1cea0d0080f9")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(26,5,5)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x06005278","0x00321688",77,"43db6ad4797e97ed994bdc3c50bd925b35592f129148bd42103009de2d51b645")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(32,4,4)
assert s["dll"]["outer_wrapper"]["frame_expression"]=="unsigned MatchMain.MchFrameCnt % 20"
assert s["dll"]["inner_method"]["wait_list"]["zero_effect"]=="store raw 2"
assert s["dll"]["inner_method"]["final_call"]["arguments"]==["seid",1.0]
assert s["dll"]["wait_decay_bridge"]["fact_id"]=="FACT-0063"
print("DLL REFEREE SOUND PATH SUMMARY: PASS")
