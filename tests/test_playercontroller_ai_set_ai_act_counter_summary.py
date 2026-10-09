#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_counter.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FAB","0x002F60DA","da602f0000008100fd350a00ebcd0200c63a","20020111a7d808"
)
assert m["parameters"]==[
    {"sequence":1,"name":"kind","metadata_type":"CounterAtkEnum","param_row_hex":"0000010063510100","flags_raw":"0x0000"},
    {"sequence":2,"name":"tm","metadata_type":"Int32","param_row_hex":"00000200d7610700","flags_raw":"0x0000"}
]
assert m["return_type_metadata"]=="Void"
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0081","tiny","0x46",8,"0x00000000"
)
assert m["locals"]==[]
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    17,"d693e192b2928d1a36497d9296bc697e14ada6ab9d936c6cbc1134813b9d07e5",
    "021f1a04289d4f000602037d4e6100042a"
)
assert s["dll"]["parameter_types"]==[
    {"sequence":1,"metadata_name":"CounterAtkEnum","typedef_rid":2550,"typedef_row_hex":"03010000a7790000000000004503b0612d50","namespace":""},
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
    ("0x0004","call","0x06004F9D","FACT-0043",26,"argument_2")
]
core_calls=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core_calls,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="50353803322a8a677c90ee71b786cfc1ce6d91e5b879abd11fb8eedc3e1f0c3b"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FDA","ChangeCounter","0x014D","call"),
    ("0x06004FF2","Process_OpponentStands_AfterHammerThrow","0x00C2","call"),
    ("0x06004FF2","Process_OpponentStands_AfterHammerThrow","0x00EC","call")
]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="86fa6e16dce76a7daf1b77e738cbdb944ac56ad2954786f05623e79b23ade63b"
assert hashlib.sha256(("0x06004FDA\n0x06004FF2\n").encode()).hexdigest()=="1c1be4e722be0dbceacee720cd826f221dd476a2e63c74fa28ad06be47e55435"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(3,2)

c=s["capture_boundary"]
assert c["playercontroller_ai_set_ai_act_counter_row_count"]==0
assert c["playercontroller_ai_set_ai_act_row_count"]==0
assert c["playercontroller_ai_change_counter_row_count"]==0
assert c["playercontroller_ai_process_opponent_stands_after_hammer_throw_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI SET AI ACT COUNTER SUMMARY: PASS")
