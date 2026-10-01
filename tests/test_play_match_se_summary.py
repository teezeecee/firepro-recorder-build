#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"play_match_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_PLAY_MATCH_SE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004970","0x002B0AE4",95,"20b2b0b4629e94a1522ac997f16d94062fd0e3ad779184615939a1ee3a794aae")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(26,5,4)
assert s["dll"]["throttle"]["frame_expression"]=="unsigned MatchMain.MchFrameCnt % 20"
assert s["dll"]["dispatch"]["arguments"]==["seid","vol","pl_idx"]
assert [(x["fact_id"],x["call_il"]) for x in s["dll"]["caller_bridges"]]==[("FACT-0015","0x0161"),("FACT-0026","0x00FF"),("FACT-0049","0x0321")]
assert s["dll"]["caller_bridges"][1]["arguments"]==[30,1.0,"PlIdx"]
assert s["dll"]["caller_bridges"][2]["arguments"]==[67,1.0,"PlIdx"]
print("DLL PLAY MATCH SE SUMMARY: PASS")
