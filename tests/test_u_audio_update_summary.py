#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_update.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_UPDATE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052E3","0x00325898",203,"f5518241de99069e054067f93d7d8145a91d461a4a5b8b78e01b5e8c364f5e26")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(2,"0x1100121F","07040c1182c1120d15118839011182c1")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(68,6,10)
assert s["dll"]["calls"]["get_current_time"]["fact_id"]=="FACT-0128"
assert s["dll"]["calls"]["song_end"]["call_ils"]==["0x0051","0x008E"]
assert s["dll"]["calls"]["play"]=={"token":"0x060052E7","fact_id":"FACT-0140","call_il":"0x00C5"}
assert s["dll"]["constants"]["sound_manager"]=={"token":"0x7008EA86","value":"Sound_Manager","load_il":"0x00A4"}
assert s["dll"]["exception_section"] is False
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
assert s["dll"]["type_closure"]["method_count"]==39
assert s["dll"]["type_closure"]["status"]=="ALL_METHODDEFS_PROVEN_DLL_AFTER_FACT_0159"
print("DLL U AUDIO UPDATE SUMMARY: PASS")
