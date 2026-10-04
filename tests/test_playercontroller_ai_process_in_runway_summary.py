#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_in_runway.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_IN_RUNWAY_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005014","0x002FDFF8","f8df2f0000008600963e0a00db490000de3a","200002"
)
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "fat","13300200d40000008e020011",2,"0x1100028E","070112a788"
)
assert (m["code_size"],m["code_sha256"])==(212,"8b5a78b8955fd7840b28de78ca0cb21326e13d2e484cd2064e163ca13953b6b4")
assert m["locals"]==[{"index":0,"kind":"class","typedef_rid":2530,"type":"Player","namespace":"","typedef_row_hex":"01001000fd480000000000005500565fa74e"}]
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj"),("0x04005FEE","Player","Zone"),
    ("0x04005FB7","Player","State"),("0x0400615D","PlayerController_AI","isThrowOppopnentToRope"),
    ("0x04006049","Player","isPinfallDef"),("0x04006117","PlayerController","padOn"),
    ("0x04006077","Player","isIntruder"),("0x040061FA","PlayerMan","inst"),
    ("0x04005FB1","Player","TargetPlIdx")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="3f9d53efc63865e184a11cc2100456ee27ffe8263eef121c0429c6343c3845f7"
assert s["dll"]["canonical_internal_calls"]==[{
    "call_il":"0x007C","opcode":"callvirt","token":"0x06005065","method":"PlayerMan.GetPlObj",
    "canonical_fact":"FACT-0109","callee_code_size":25,
    "callee_code_sha256":"32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8"
}]
assert s["dll"]["external_memberrefs"]==[]
assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x000C","beq","0x0024"),("0x001D","beq","0x0024"),("0x0031","bne.un","0x0038"),
    ("0x004A","brfalse","0x005C"),("0x0057","br","0x00D2"),("0x0067","brfalse","0x00C9"),
    ("0x008A","beq","0x009C"),("0x0097","bne.un","0x00A6"),("0x00AD","beq","0x00C7"),
    ("0x00B9","beq","0x00C7")
]
state_gate=s["dll"]["branch_sites"][2]
assert state_gate["comparison"]=="PlObj.State != raw 22"
assert state_gate["target_effect"]=="continue"
assert state_gate["fallthrough_effect"]=="return false"
assert m["exact_flow"][1]=="if this.PlObj.State is raw 22 return false; every other raw State continues"
assert [x["raw_boolean"] for x in s["dll"]["return_sites"]]==[False,False,True,True,False,True,False]
assert s["dll"]["direct_in_assembly_references"]==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x0322","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="473134c674093f35692fff64e08399f97c47a6b6abb21b9dafb333df369c718d"
assert s["dll"]["normalized_caller_token_set_sha256"]=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"
c=s["capture_boundary"]
assert c["playercontroller_ai_process_in_runway_row_count"]==0
assert c["playerman_get_pl_obj_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS IN RUNWAY SUMMARY: PASS")
