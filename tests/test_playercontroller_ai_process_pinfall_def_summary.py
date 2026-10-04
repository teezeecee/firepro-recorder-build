#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_pinfall_def.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_PINFALL_DEF_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005023","0x002FF78C","8cf72f0000008100ea3f0a00db490000de3a","200002"
)
assert m["parameters"]==[]
assert m["return_type"]=={"metadata_type":"Boolean"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0081","fat","133003006300000000000000",3,"0x00000000"
)
assert m["locals"]==[]
assert (m["code_size"],m["code_sha256"])==(
    99,"8cd99966c2f677c3c5adb0b93e5ff520f7cccecc1d4c80f260694ad88c091a0a"
)
assert m["body_hex"]=="027b4a6100047b496000043a02000000162a027b4a6100047b526000043902000000162a027b646100043a0d0000000228d44f000602177d64610004027b63610004027b656100041f3c5d913908000000021f207d18610004021f207d17610004172a"

assert [(x["token"],x["owner"],x["name"],x["signature_blob_hex"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj","0612a788"),
    ("0x04006049","Player","isPinfallDef","0602"),
    ("0x04006052","Player","isLose","0602"),
    ("0x04006164","PlayerController_AI","initializedRapidPushTbl","0602"),
    ("0x04006163","PlayerController_AI","rapidPushTbl","061d02"),
    ("0x04006165","PlayerController_AI","frmCnt","0608"),
    ("0x04006118","PlayerController","padPush","0611904c"),
    ("0x04006117","PlayerController","padOn","0611904c")
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[
    ("0x0001","ldfld","0x0400614A"),
    ("0x0006","ldfld","0x04006049"),
    ("0x0013","ldfld","0x0400614A"),
    ("0x0018","ldfld","0x04006052"),
    ("0x0025","ldfld","0x04006164"),
    ("0x0037","stfld","0x04006164"),
    ("0x003D","ldfld","0x04006163"),
    ("0x0043","ldfld","0x04006165"),
    ("0x0054","stfld","0x04006118"),
    ("0x005C","stfld","0x04006117")
]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="62def3dc7a912f13980e15fee2bf5c126ec580ae7708489859903cbb18ef75b5"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0030","call","0x06004FD4","FACT-0238")
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="13fbb5ce22b7d241c4f2425461755f7b0fc66b497be3e43ea0e3386a0b069418"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x01C1","opcode":"call"
}]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="074fc86e10e9aca5ac69ddab4f0a8a69a06a5bab38fb35cf79f99e105232a27d"
assert hashlib.sha256(("0x0600502B\n").encode()).hexdigest()=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)

c=s["capture_boundary"]
assert c["playercontroller_ai_process_pinfall_def_row_count"]==0
assert c["playercontroller_ai_make_rapid_push_tbl_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS PINFALL DEF SUMMARY: PASS")
