#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_go_front_grapple.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_GO_FRONT_GRAPPLE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004F9F","0x002F5FDE","de5f2f0000008100e1340a00bca80200ae3a","20020111870c08"
)
assert m["parameters"]==[
    {"sequence":1,"name":"skill","metadata_type":"SkillSlotEnum","param_row_hex":"0000010029a40200","flags_raw":"0x0000"},
    {"sequence":2,"name":"tm","metadata_type":"Int32","param_row_hex":"00000200d7610700","flags_raw":"0x0000"}
]
assert (m["return_type_metadata"],m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"],m["locals"])==(
    "Void","0x0000","0x0081","tiny","0x42",8,"0x00000000",[]
)
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    16,"a56c6e589ca381688f49aa4eb215ea17e3016373b6e0c445e186af503396aecc",
    "021804289d4f000602037d606100042a"
)
assert s["dll"]["parameter_types"][0]=={
    "sequence":1,"metadata_name":"SkillSlotEnum","typedef_rid":451,
    "typedef_row_hex":"01010000b7170000000000004503e80e6f11","namespace":""
}
assert s["dll"]["fields"]==[
    {"token":"0x04006160","owner":"PlayerController_AI","name":"nextSkill","field_row_hex":"0100daf30300720a0000","signature_blob_hex":"0611870c","metadata_type":"SkillSlotEnum"}
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[("0x000A","stfld","0x04006160")]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="24d4bdb6d1f5f6686df83a3a922b09a121debc0bd5e327702efd7898e66e4a2c"
calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"],x["raw_argument_1"],x["argument_2_source"]) for x in calls]==[
    ("0x0003","call","0x06004F9D","FACT-0043",2,"argument_2")
]
call_core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="4dfec0c9d6a73c697ad119023c11863164928934ceea4d69fb242dd0f63a6bb8"
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FF5","Process_OpponentStands_Stun","0x01C7","call")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="4da84c8c17a929a917c7dbc7acfbad84133979cc51a1ed70e7501b4d8b15782b"
assert s["dll"]["normalized_caller_token_set_sha256"]=="e48a1362b562dd41abab3f01e7ea30008538d8f7ac165edbac1edc490495f47d"
c=s["capture_boundary"]
assert c["playercontroller_ai_set_ai_act_go_front_grapple_row_count"]==0
assert c["playercontroller_ai_set_ai_act_row_count"]==0
assert c["playercontroller_ai_process_opponent_stands_stun_row_count"]==0
assert c["promoted_as_evidence"] is False
sel=s["selection_boundary"]
assert sel["smaller_open_wrapper"]["code_size"]==15
assert sel["smaller_open_wrapper"]["dependency_code_size"]==569
assert sel["selected_leaf"]["code_size"]==16
assert sel["selected_leaf"]["canonical_child_fact_id"]=="FACT-0043"
print("DLL PLAYERCONTROLLER AI SET AI ACT GO FRONT GRAPPLE SUMMARY: PASS")
