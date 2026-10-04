#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"misc_shuffle.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_MISC_SHUFFLE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004AA7","0x002B8560","60852b00000096003a060a0029b302005b37","0002011d0808"
)
assert m["parameters"]==[
    {"sequence":1,"name":"a","metadata_type":"Int32[]","param_row_hex":"000001001d000600","flags_raw":"0x0000"},
    {"sequence":2,"name":"num","metadata_type":"Int32","param_row_hex":"00000200122b0100","flags_raw":"0x0000"}
]
assert m["return_type"]=={"metadata_type":"Void"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0096","fat","13300600410000003a000011",6,"0x1100003A"
)
assert (m["code_size"],m["code_sha256"])==(65,"d8e87deae43facf68b16b094188ade6c7db1915caa3c59031cb85f891529b5c1")
assert m["body_hex"]=="0320000100003e010000002a160a38160000007e3159000406162000000100287b4900069e0617580a06033fe3ffffff7e3159000402161603175928a14a00062a"

ls=s["dll"]["local_signature"]
assert (ls["token"],ls["standalone_sig_row_hex"],ls["blob_hex"])==("0x1100003A","f25a0100","070108")
assert ls["locals"]==[{"index":0,"metadata_type":"Int32"}]

assert s["dll"]["fields"]==[{
    "token":"0x04005931","owner":"Misc","name":"rnd_prm",
    "field_row_hex":"1100ce9703008d030000","signature_blob_hex":"061d08","metadata_type":"Int32[]"
}]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[
    ("0x0013","ldsfld","0x04005931"),("0x0030","ldsfld","0x04005931")
]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="e6ba82e635d388e5aa115a3d27cabaef6c0a579854af0a03b3796ea70a5da6eb"

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x001F","call","0x0600497B","FACT-0032"),
    ("0x003B","call","0x06004AA1","FACT-0236")
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="feca82b4b783e3d3795c0db2e1cb632d5b075042b4148f1af978454a8df0248e"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert refs==[{
    "caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"MakeRapidPushTbl",
    "caller_token":"0x06004FD4","caller_rva":"0x002F8DC4","caller_code_size":308,
    "caller_code_sha256":"63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7",
    "call_il":"0x00E9","opcode":"call"
}]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="512cb7970f8f6cfc59c8ef156984843b2f463ae89900bf16611cc6bbdcef606c"
assert hashlib.sha256(("0x06004FD4\n").encode()).hexdigest()=="57c7e8247b57b3415421d95222f7f487d4cc22ba7443e55276dcd046ae08bb29"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)

c=s["capture_boundary"]
assert c["misc_shuffle_row_count"]==0
assert c["misc_quicksort_int_row_count"]==0
assert c["matchrandom_range_row_count"]==0
assert c["playercontroller_ai_make_rapid_push_tbl_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL MISC SHUFFLE SUMMARY: PASS")
