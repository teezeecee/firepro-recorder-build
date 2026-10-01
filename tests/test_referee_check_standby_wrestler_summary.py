#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_check_standby_wrestler.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_CHECK_STANDBY_WRESTLER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050A8","0x003094D0",103,"ee9e9c47f5d28bf25f68a8af0c22b9a0f794b042d30cbdc9dbf23ab310a3964d")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(39,8,2)
assert s["dll"]["entry"]["required_raw_value"]==4
assert s["dll"]["scan"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":7}
assert s["dll"]["scan"]["appear_time_field"]=={"name":"Player.royalRambleAppearTime","token":"0x04006035"}
assert s["dll"]["direct_callers"]==[{"fact_id":"FACT-0091","type":"Referee","method":"CheckMatchEnd","token":"0x060050A9","rva":"0x00309544","call_il":"0x0007","opcode":"call"}]
print("DLL REFEREE CHECK STANDBY WRESTLER SUMMARY: PASS")
