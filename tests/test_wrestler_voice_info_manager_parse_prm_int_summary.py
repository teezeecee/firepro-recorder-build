#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_manager_parse_prm_int.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_MANAGER_PARSE_PRM_INT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060011E9","0x0006F210","0004080e0811aa3c0e")
assert (m["code_size"],m["code_sha256"])==(96,"12e664e407030c367665e38466387ae43d43134ae0c1e183c918aa89ee3e34ba")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(3,"0x11000002","07020808")
assert s["dll"]["strings"]==[{"token":"0x70007CF6","value":"N","load_il":"0x0015"},{"token":"0x7000046F","value":" ","load_il":"0x002E"}]
assert s["dll"]["exception_section"]["sha256"]=="94de01fa84600402f67fcb97192f92de809361ea7d8c69299fba78f3037503ac"
r=s["dll"]["inbound_direct_reference"]
assert (r["caller_token"],r["call_il"],r["callee_token"])==("0x060011EA","0x0243","0x060011E9")
print("DLL WRESTLER VOICE INFO MANAGER PARSE PRM INT SUMMARY: PASS")
