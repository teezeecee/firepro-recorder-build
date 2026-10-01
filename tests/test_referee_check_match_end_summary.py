#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_check_match_end.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_CHECK_MATCH_END_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050A9","0x00309544",168,"14d88238c271a882dd9fe1c4d3a0fdd732d43a830be6728478f50747326aab9f")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(52,12,7)
assert s["dll"]["entry"]["check_standby"]["true_effect"]=="return"
assert s["dll"]["count_flow"]["zero_count"]["condition"]=="returned count == 0"
d=s["dll"]["nonzero_dispatch"]
assert [x["callee_token"] for x in d]==["0x060050A5","0x060050A4","0x060050A6","0x060050A7"]
assert d[1]["raw_value"]==4
assert d[3]["raw_value"]==1
assert s["dll"]["direct_callers"]==[{"fact_id":"FACT-0074","type":"Referee","method":"UpdateReferee","token":"0x060050AF","rva":"0x00309E9C","call_il":"0x007A","opcode":"call"}]
print("DLL REFEREE CHECK MATCH END SUMMARY: PASS")
