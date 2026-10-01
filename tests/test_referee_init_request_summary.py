#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_init_request.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_INIT_REQUEST_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x06005079","0x003059EC",167,"e19f6d9ac4f9301e31c9e58d32ed267743c5bd5e6c44ae16a1aa04e4e02f8e24")
assert (a["instruction_count"],a["branch_instruction_count"])==(58,3)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x06005096","0x00307E2C",92,"460f863df8f05cabe8f18840b94a8b6a3bdd22505263f3baf51edd0b900be7b6")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(40,0,0)
assert s["dll"]["init"]["parts_scale_loop"]["raw_index_range"]=={"min_inclusive":0,"max_inclusive":8}
assert s["dll"]["init"]["parts_scale_loop"]["comparison_opcode"]=="bge.un"
assert s["dll"]["init"]["parts_scale_loop"]["replacement_when_branch_not_taken"]=="target[index] = 1.0f"
assert s["dll"]["init"]["pl_pos"]["values"]=={"x":0.0,"y":0.0,"z":1.0}
assert len(s["dll"]["request"]["field_writes"])==13
assert s["dll"]["request"]["field_writes"][0]["field"]=="SkillID"
assert s["dll"]["request"]["field_writes"][3]=={"field":"reqAnmInit","token":"0x040062BF","value":1}
assert [(x["init_il"],x["request_il"]) for x in s["dll"]["fact_0067_bridges"]]==[("0x0156","0x01FB"),("0x00EB","0x010B")]
print("DLL REFEREE INIT REQUEST SUMMARY: PASS")
