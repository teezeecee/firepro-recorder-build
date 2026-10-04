#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_run_attack_after_hammer_throw.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_RUN_ATTACK_AFTER_HAMMER_THROW_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FA8","0x002F60A4","a4602f0000008100a2350a00e3cd0200c03a","20020111a7d008"
)
assert m["parameters"]==[
    {"sequence":1,"name":"kind","metadata_type":"RunAtkEnum","param_row_hex":"0000010063510100","flags_raw":"0x0000"},
    {"sequence":2,"name":"tm","metadata_type":"Int32","param_row_hex":"00000200d7610700","flags_raw":"0x0000"}
]
assert m["return_type_metadata"]=="Void"
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0081","tiny","0x46",8,"0x00000000"
)
assert m["locals"]==[]
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    17,"2db5766f26c4ae6a892727404beaf78a217dfffc6413441ad9b174a58fcb2a7c",
    "021f0e04289d4f000602037d4e6100042a"
)
assert s["dll"]["parameter_types"]==[
    {"sequence":1,"metadata_name":"RunAtkEnum","typedef_rid":2548,"typedef_row_hex":"0301000093790000000000004503a8612d50","namespace":""},
    {"sequence":2,"metadata_name":"Int32"}
]
assert s["dll"]["fields"]==[{
    "token":"0x0400614E","owner":"PlayerController_AI","name":"aiActPrm",
    "field_row_hex":"0100dbf2030001000000","signature_blob_hex":"0608","metadata_type":"Int32"
}]
fa=s["dll"]["field_accesses"]
assert fa==[{"il":"0x000B","opcode":"stfld","token":"0x0400614E","source":"argument_1"}]
core_fa=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core_fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="d5718d050bd7e511e13bf4a3689b08e71f09a2eb9147f8bf1ef35f45a30e95ca"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"],x["raw_argument_1"],x["argument_2_source"]) for x in calls]==[
    ("0x0004","call","0x06004F9D","FACT-0043",14,"argument_2")
]
core_calls=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core_calls,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="50353803322a8a677c90ee71b786cfc1ce6d91e5b879abd11fb8eedc3e1f0c3b"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"",
    "caller_method":"Process_OpponentStands_AfterHammerThrow",
    "caller_token":"0x06004FF2","caller_rva":"0x002FB3C0","caller_code_size":248,
    "caller_code_sha256":"f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3",
    "call_il":"0x00D7","opcode":"call"
}]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="1279b165d1ce55d686cbf9b888cdf38e23ad97ade09f75cf69345a0ec7a71242"
assert hashlib.sha256(("0x06004FF2\n").encode()).hexdigest()=="ce6cb38f9a20f9bbe7382609d15ffc01ef848e1554a79b07cbbe62742f9a3d39"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)

c=s["capture_boundary"]
assert c["playercontroller_ai_set_ai_act_run_attack_after_hammer_throw_row_count"]==0
assert c["playercontroller_ai_set_ai_act_row_count"]==0
assert c["playercontroller_ai_process_opponent_stands_after_hammer_throw_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI SET AI ACT RUN ATTACK AFTER HAMMER THROW SUMMARY: PASS")
