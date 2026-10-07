#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_run_atk_to_stunned_opponent.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_RUN_ATK_TO_STUNNED_OPPONENT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FA9","0x002F60B6","b6602f0000008100c5350a00e3cd0200c23a","20020111a7d008"
)
assert m["parameters"]==[
    {"sequence":1,"name":"kind","metadata_type":"RunAtkEnum","param_row_hex":"0000010063510100","flags_raw":"0x0000"},
    {"sequence":2,"name":"tm","metadata_type":"Int32","param_row_hex":"00000200d7610700","flags_raw":"0x0000"}
]
assert (m["return_type_metadata"],m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"],m["locals"])==(
    "Void","0x0000","0x0081","tiny","0x46",8,"0x00000000",[]
)
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    17,"14e962309d03585018de393653c8b4dd4508649084262fbd1bff8fcd9a70e49f",
    "021f0f04289d4f000602037d4e6100042a"
)
assert s["dll"]["parameter_types"]==[
    {"sequence":1,"metadata_name":"RunAtkEnum","typedef_rid":2548,"typedef_row_hex":"0301000093790000000000004503a8612d50","namespace":""},
    {"sequence":2,"metadata_name":"Int32"}
]
assert s["dll"]["fields"]==[
    {"token":"0x0400614E","owner":"PlayerController_AI","name":"aiActPrm","field_row_hex":"0100dbf2030001000000","signature_blob_hex":"0608","metadata_type":"Int32"}
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[("0x000B","stfld","0x0400614E")]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="d5718d050bd7e511e13bf4a3689b08e71f09a2eb9147f8bf1ef35f45a30e95ca"
calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"],x["raw_argument_1"],x["argument_2_source"]) for x in calls]==[
    ("0x0004","call","0x06004F9D","FACT-0043",15,"argument_2")
]
call_core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="50353803322a8a677c90ee71b786cfc1ce6d91e5b879abd11fb8eedc3e1f0c3b"
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"",
    "caller_method":"Process_OpponentStands_Stun",
    "caller_token":"0x06004FF5","caller_rva":"0x002FB600","caller_code_size":529,
    "caller_code_sha256":"5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037",
    "call_il":"0x0119","opcode":"call"
}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["normalized_reference_map_sha256"]=="e9d0ee20e1f8a635e56757aa09a1b5fd5349358ca7dbfc4a5cf3d32d938561ff"
assert s["dll"]["normalized_caller_token_set_sha256"]=="e48a1362b562dd41abab3f01e7ea30008538d8f7ac165edbac1edc490495f47d"
c=s["capture_boundary"]
assert c["playercontroller_ai_set_ai_act_run_atk_to_stunned_opponent_row_count"]==0
assert c["playercontroller_ai_set_ai_act_row_count"]==0
assert c["playercontroller_ai_process_opponent_stands_stun_row_count"]==0
assert c["promoted_as_evidence"] is False
sel=s["selection_boundary"]
assert sel["smaller_blocked_wrapper"]["code_size"]==15
assert sel["smaller_blocked_wrapper"]["dependency_code_size"]==569
assert sel["smaller_already_canonical_wrapper"]["code_size"]==16
assert sel["smaller_already_canonical_wrapper"]["fact_id"]=="FACT-0042"
assert sel["selected_leaf"]["code_size"]==17
assert sel["selected_leaf"]["canonical_child_fact_id"]=="FACT-0043"
print("DLL PLAYERCONTROLLER AI SET AI ACT RUN ATK TO STUNNED OPPONENT SUMMARY: PASS")
