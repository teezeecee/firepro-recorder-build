#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_manager_parse.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_MANAGER_PARSE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060011EA","0x0006F28C","200001")
assert (m["code_size"],m["code_sha256"])==(654,"51600ca58d83133003e36ec3afd834efa865af3cd33749c16af5e5f0e68d9a1d")
assert (m["max_stack"],m["local_signature_token"])==(6,"0x1100034E")
r=s["dll"]["raw_structure"]
assert (r["split_character_decimal"],r["outer_column_step"],r["dlc_iteration_count"],r["parse_prm_digit_count"])==(9,4,16,2)
assert s["dll"]["internal_calls"]["parse_prm_int"]=={"token":"0x060011E9","call_il":"0x0243","canonical_fact":"FACT-0185"}
assert s["dll"]["exception_section"]["sha256"]=="70456e60bd6570383da3640a430a402719684d70d8183af136792f90f11df539"
assert s["dll"]["inbound_direct_reference"]["canonical_fact"]=="FACT-0184"
print("DLL WRESTLER VOICE INFO MANAGER PARSE SUMMARY: PASS")
