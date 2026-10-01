#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"set_ai_act_core.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_CORE_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["signature_blob_hex"],a["code_size"],a["code_sha256"])==(
 "0x06004F9D","0x002F5F54","20020111a7bc08",102,"58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065")
assert a["parameters"]==[{"sequence":1,"name":"act","type":"AIActEnum"},{"sequence":2,"name":"cnt","type":"Int32"}]
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(39,4,2)
assert (b["token"],b["rva"],b["signature_blob_hex"],b["code_size"],b["code_sha256"])==(
 "0x06004FAC","0x002F60EC","20010108",8,"cff3981d35f0878efae84ea0b7f25c9c403437bc3e9413041ba509fbb361fa1a")
assert s["dll"]["fields"]["aiAct"]["token"]=="0x0400614B"
assert s["dll"]["fields"]["aiActDuration"]["token"]=="0x0400614C"
assert s["dll"]["fields"]["aiActStep"]["token"]=="0x0400614D"
assert s["dll"]["fields"]["dragOpponentCnt"]["token"]=="0x0400616B"
assert s["dll"]["set_ai_act"]["raw_action_values"]==[19,20]
assert s["dll"]["caller_bridges"][1]["arguments"]==[17,768]
print("DLL SET AI ACT CORE SUMMARY: PASS")
