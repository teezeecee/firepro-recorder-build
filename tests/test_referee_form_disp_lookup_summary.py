#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_form_disp_lookup.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_FORM_DISP_LOOKUP_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005098","0x00308040","200012a9cc",104,"edf4f6904d007e70cf4d2cec22ab4c31f61d4898d18fd3107d886d2239a5a964")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(40,4,0)
assert [x["opcode"] for x in s["dll"]["exact_lookup"] if "opcode" in x]==["blt","blt","blt","blt"]
assert s["dll"]["fact_0070_bridge"]["call_ils"]==["0x00DF","0x0109"]
assert s["dll"]["fields"]["form_disp_list"]=={"name":"formDispList","token":"0x04007C9F"}
print("DLL REFEREE FORM DISP LOOKUP SUMMARY: PASS")
