#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_set_current_time.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SET_CURRENT_TIME_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052D7","row_hex":"a05732000000e609728a070074480100553d","rva":"0x003257A0"}
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052D7","0x003257A0","2001011182c1")
assert (m["code_size"],m["code_sha256"])==(24,"c09298a196302aaeb2cd6734a8b2297724c09221a9602d15e85257482f52199c")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(8,1,1)
assert s["dll"]["field"]["token"]=="0x040087E3"
assert s["dll"]["call"]["token"]=="0x0A000FB9"
assert [x["call_il"] for x in s["dll"]["fact_0140_bridges"]]==["0x018D","0x019F"]
print("DLL U AUDIO SET CURRENT TIME SUMMARY: PASS")
