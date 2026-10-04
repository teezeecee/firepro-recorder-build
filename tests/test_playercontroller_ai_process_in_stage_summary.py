#!/usr/bin/env python3
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_in_stage.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_IN_STAGE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005013","0x002FDEE8","e8de2f0000008100863e0a00db490000de3a","200002"
)
assert (m["method_attributes_raw"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(
    "0x0081","13300200040100008e020011",2,"0x1100028E","070112a788"
)
assert (m["code_size"],m["code_sha256"])==(260,"689a04f4f28bef50f618fd9599e843cc189efae42457ebde181d5429c34bbc5d")
assert m["locals"]==[{"index":0,"kind":"class","typedef_rid":2530,"type":"Player","namespace":"","typedef_row_hex":"01001000fd480000000000005500565fa74e"}]
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj"),("0x04005FEE","Player","Zone"),
    ("0x04005FB7","Player","State"),("0x0400615D","PlayerController_AI","isThrowOppopnentToRope"),
    ("0x04006049","Player","isPinfallDef"),("0x04006117","PlayerController","padOn"),
    ("0x04006077","Player","isIntruder"),("0x040061FA","PlayerMan","inst"),
    ("0x04005FB1","Player","TargetPlIdx"),("0x04005FAA","Player","PlPos")
]
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["member_fields"]]==[
    ("0x0A000009","UnityEngine.Vector3","x"),("0x0A00000A","UnityEngine.Vector3","y")
]
assert s["dll"]["normalized_field_access_map_sha256"]=="24c3e38f3901443214d521c6eebcc6eaab6a535d3154f5d6e2c70a98b333bbe2"
assert s["dll"]["canonical_internal_calls"]==[{
    "call_il":"0x006C","opcode":"callvirt","token":"0x06005065","method":"PlayerMan.GetPlObj",
    "canonical_fact":"FACT-0109","callee_code_size":25,
    "callee_code_sha256":"32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8"
}]
assert s["dll"]["external_memberref_calls"]==[]
assert [(x["il"],x["opcode"],x["target_il"]) for x in s["dll"]["branch_sites"]]==[
    ("0x000D","beq","0x0014"),("0x0021","bne.un","0x0028"),("0x003A","brfalse","0x004C"),
    ("0x0047","br","0x0102"),("0x0057","brfalse","0x00C8"),("0x007A","beq","0x00C6"),
    ("0x0087","beq","0x00C6"),("0x00AC","ble.un","0x00BD"),("0x00B8","br","0x00C4"),
    ("0x00E8","ble.un","0x00F9"),("0x00F4","br","0x0100")
]
state_gate=s["dll"]["branch_sites"][1]
assert state_gate["comparison"]=="PlObj.State != raw 22"
assert state_gate["target_effect"]=="continue"
assert state_gate["fallthrough_effect"]=="return false"
assert m["exact_flow"][1]=="if this.PlObj.State is raw 22 return false; every other raw State continues"
for gate in (s["dll"]["branch_sites"][7],s["dll"]["branch_sites"][9]):
    assert gate["comparison"]=="raw stack order PlPos.y then PlPos.x"
    assert gate["target_effect"]=="padOn = raw 4"
    assert gate["fallthrough_effect"]=="padOn = raw 2"
assert s["dll"]["raw_writes"]==[
    {"field":"PlayerController_AI.isThrowOppopnentToRope","raw_value":False,"value_il":"0x0029","write_il":"0x002A"},
    {"field":"PlayerController.padOn","raw_value":32,"value_il":"0x0040","write_il":"0x0042"},
    {"field":"PlayerController.padOn","raw_value":2,"value_il":"0x00B2","write_il":"0x00B3"},
    {"field":"PlayerController.padOn","raw_value":4,"value_il":"0x00BE","write_il":"0x00BF"},
    {"field":"PlayerController.padOn","raw_value":2,"value_il":"0x00EE","write_il":"0x00EF"},
    {"field":"PlayerController.padOn","raw_value":4,"value_il":"0x00FA","write_il":"0x00FB"}
]
assert [x["raw_boolean"] for x in s["dll"]["return_sites"]]==[False,False,True,False,True,False]
assert s["dll"]["direct_in_assembly_references"]==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x0316","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="c7c0815170574360afc45486afe6ceb91f06badddb65f76a85f5642b16651c90"
assert s["dll"]["normalized_caller_token_set_sha256"]=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"
c=s["capture_boundary"]
assert c["playercontroller_ai_process_in_stage_row_count"]==0
assert c["playerman_get_pl_obj_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS IN STAGE SUMMARY: PASS")
