#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"is_s1_waza.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SKILLDATAMAN_IS_S1_WAZA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06005266","0x0031FF75","00010212a9a8",40,"7693ac0d94e82285e39d223199a9bae9209d6b4f75f765839ddba129cd85fbd0")
assert m["parameters"]==[{"sequence":1,"name":"w","type":"SkillData"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(15,3,0)
assert s["dll"]["field"]=={"name":"skillType","token":"0x04007C51"}
assert s["dll"]["raw_true_values"]==[0,1,9]
assert [x["opcode"] for x in s["dll"]["exact_branch_graph"][:3]]==["brfalse","beq","bne.un"]
assert [(x["fact_id"],x["call_il"]) for x in s["dll"]["caller_bridges"]]==[("FACT-0021","0x03AD"),("FACT-0022","0x0272")]
print("DLL IS S1 WAZA SUMMARY: PASS")
