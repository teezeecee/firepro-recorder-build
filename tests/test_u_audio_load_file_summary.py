#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_load_file.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_LOAD_FILE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052E4","0x00325970","2001010e")
assert (m["code_size"],m["code_sha256"])==(65,"b5b74da6ab2322d1895635e2add04dd52f9ee9ca4a3846825a9b6fe4631e3ef4")
assert m["parameters"]==[{"sequence":1,"name":"targetFileIN","type":"String"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(21,2,4)
assert s["dll"]["fields"]["target_file"]["token"]=="0x040087E6"
assert s["dll"]["fields"]["loaded_target"]["token"]=="0x040087F1"
assert s["dll"]["calls"]["get_u_audio"]["call_ils"]==["0x0013","0x0035"]
assert s["dll"]["calls"]["backend_load_file"]["token"]=="0x0A000FC2"
assert [x["call_il"] for x in s["dll"]["fact_0133_bridges"]]==["0x00E3","0x019A"]
print("DLL U AUDIO LOAD FILE SUMMARY: PASS")
