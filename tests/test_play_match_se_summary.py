#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"play_match_se.summary.json").read_text())
assert s["dataset_id"]=="DLL_MATCHMISC_PLAY_MATCH_SE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004970","0x002B0AE4",95,"20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(26,5,4)
assert s["dll"]["throttle"]["expression"]=="unsigned MchFrameCnt % 20"
assert s["dll"]["dispatch"]["arguments"]==["seid","vol","pl_idx"]
print("DLL PLAY MATCH SE SUMMARY: PASS")
