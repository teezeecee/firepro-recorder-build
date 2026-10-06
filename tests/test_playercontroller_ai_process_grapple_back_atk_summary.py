#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_grapple_back_atk.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_GRAPPLE_BACK_ATK_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004FE3","0x002F9D40","409d2f0000008100a43a0a005c480000d43a","200001"
)
assert m["parameters"]==[]
assert m["return_type_metadata"]=="Void"
assert (m["impl_flags_raw"],m["method_attributes_raw"])==("0x0000","0x0081")
assert (m["header_format"],m["fat_header_bytes_raw"],m["max_stack"],m["init_locals"],m["local_signature_token"])==(
    "fat","133003004e01000011110011",3,True,"0x11001111"
)
assert (m["local_signature_row_hex"],m["local_signature_blob_hex"])==(
    "d0cf0200","070612863012a78812870411a7c41d081185ec"
)
assert [x["metadata_type"] for x in m["locals"]]==[
    "AIParam","Player","SkillSlotData","DamageLevelEnum_LMH","Int32[]","AIOpt_BackGrapple"
]
assert (m["code_size"],m["code_sha256"])==(
    334,"cd3deb24c9c49730460a7d595105d48c8d342600d53947160adc8feaffd546b0"
)
assert (m["instruction_count"],m["field_access_count"],m["branch_instruction_count"],m["methoddef_call_site_count"],m["memberref_method_call_count"])==(105,34,13,5,0)

fa=s["dll"]["field_accesses"]
assert len(fa)==34
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="3b92933eebc8580ee0cffd0630322850d175e377c3ed1a9cbb24a81b4f81081b"
assert s["dll"]["external_memberref_fields"]==[{
    "token":"0x0A00000A","name":"y","memberref_row_hex":"31000000e1b6000014000000",
    "signature_blob_hex":"060c","parent_coded_index_raw":49,
    "parent_type_ref":{"rid":6,"name":"Vector3","namespace":"UnityEngine","row_hex":"0600f4a9000080a60000"},
    "access_ils":["0x0111","0x012B"]
}]

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0021","callvirt","0x06005065","FACT-0109"),
    ("0x007B","call","0x0600116D","FACT-0035"),
    ("0x00A7","call","0x06004F9B","FACT-0038"),
    ("0x00CB","call","0x0600495B","FACT-0245"),
    ("0x0147","call","0x06004FF2","FACT-0246")
]
core_calls=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core_calls,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="0b99eec8230541d7e5307c71eab3b3b16e1a01134f19757a283843813f02798b"
assert s["dll"]["external_memberref_method_calls"]==[]

branches=s["dll"]["branch_map"]
assert len(branches)==13
assert hashlib.sha256(json.dumps(branches,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="5d817c66627c6512920a24cde32fb45f88ed13d93135db64ae4695b2c7770abe"

refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Process_Grapple",
    "caller_token":"0x06004FE4","caller_rva":"0x002F9E9C","caller_code_size":709,
    "caller_code_sha256":"221fc977746121dd811fe1d13e59502c160992648d03561b81e6b7555e04ea42",
    "call_il":"0x0193","opcode":"call"
}]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="de2e286c63882ce40f5d0baa1e135f274e7d2090f0832b30e01c5042281a6d79"
assert hashlib.sha256(("0x06004FE4\n").encode()).hexdigest()=="d02a9d70f80b20a5296e5cd052dbe75e74bbd8fde7609e8a8f76768a9b75f199"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)

c=s["capture_boundary"]
for k,v in c.items():
    if k.endswith("_row_count"):
        assert v==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS GRAPPLE BACK ATK SUMMARY: PASS")
