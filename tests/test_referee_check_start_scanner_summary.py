#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_check_start_scanner.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_CHECK_START_SCANNER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050A0","0x00308898",123,"a77f5e25b67af39e16a62e15a171465293dbae28e3851625a93c49f9ef820868")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(43,11,3)
assert s["dll"]["scan"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":7}
assert s["dll"]["scan"]["sleep_field"]=={"name":"Player.isSleep","token":"0x04006057"}
i=s["dll"]["inner_overload"]
assert (i["token"],i["rva"],i["code_size"],i["code_sha256"])==("0x060050A1","0x00308920",1112,"8531aa20df597f7d7a37246779e58c39c7c7a2fdc6e34d4d38dcd1fd56f6f7e5")
assert i["parameters"]==[{"sequence":1,"name":"pl_idx","type":"Int32"}]
assert s["dll"]["direct_callers"]==[{"fact_id":"FACT-0074","type":"Referee","method":"UpdateReferee","token":"0x060050AF","rva":"0x00309E9C","call_il":"0x005C","opcode":"call"}]
print("DLL REFEREE CHECK START SCANNER SUMMARY: PASS")
