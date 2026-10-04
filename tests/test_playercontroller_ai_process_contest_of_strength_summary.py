#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_process_contest_of_strength.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_PROCESS_CONTEST_OF_STRENGTH_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06005026","0x002FF930","30f92f000000810029400a00db490000de3a","200002"
)
assert m["parameters"]==[]
assert m["return_type"]=={"metadata_type":"Boolean"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0081","fat","133003004a00000000000000",3,"0x00000000"
)
assert m["locals"]==[]
assert (m["code_size"],m["code_sha256"])==(
    74,"55f0bb53b03f366663707771d918a6cbe62aae003288dd23d7b1588c027de95b"
)
assert m["body_hex"]=="027b4a6100047bb75f00041f173b02000000162a027b646100043a0d0000000228d44f000602177d64610004027b63610004027b656100041f3c5d913907000000021e7d18610004172a"

assert [(x["token"],x["owner"],x["name"],x["signature_blob_hex"]) for x in s["dll"]["fields"]]==[
    ("0x0400614A","PlayerController_AI","PlObj","0612a788"),
    ("0x04005FB7","Player","State","0611a828"),
    ("0x04006164","PlayerController_AI","initializedRapidPushTbl","0602"),
    ("0x04006163","PlayerController_AI","rapidPushTbl","061d02"),
    ("0x04006165","PlayerController_AI","frmCnt","0608"),
    ("0x04006118","PlayerController","padPush","0611904c")
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[
    ("0x0001","ldfld","0x0400614A"),
    ("0x0006","ldfld","0x04005FB7"),
    ("0x0015","ldfld","0x04006164"),
    ("0x0027","stfld","0x04006164"),
    ("0x002D","ldfld","0x04006163"),
    ("0x0033","ldfld","0x04006165"),
    ("0x0043","stfld","0x04006118")
]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="2c44695ad1830ef56baf46c360c152a68de7eab4d5a005f65d85dea7283a0f0d"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0020","call","0x06004FD4","FACT-0238")
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="65b2084dd4bab12ed5c457cbcf9d5cc4f24e35b571d09418a1160dcbfa9f8990"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Update",
    "caller_token":"0x0600502B","caller_rva":"0x002FFC68","caller_code_size":984,
    "caller_code_sha256":"6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9",
    "call_il":"0x01D9","opcode":"call"
}]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="d426f647d403f962546907a3d28b9a2627685e70a8906960ee8c6ea993b11eba"
assert hashlib.sha256(("0x0600502B\n").encode()).hexdigest()=="8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)

c=s["capture_boundary"]
assert c["playercontroller_ai_process_contest_of_strength_row_count"]==0
assert c["playercontroller_ai_make_rapid_push_tbl_row_count"]==0
assert c["playercontroller_ai_update_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI PROCESS CONTEST OF STRENGTH SUMMARY: PASS")
