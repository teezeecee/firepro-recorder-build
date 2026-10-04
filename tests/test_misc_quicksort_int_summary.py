#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"misc_quicksort_int.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_MISC_QUICKSORT_INT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004AA1","0x002B8318","18832b0000009600e2050a0002b302004537","0005011d081d08080808"
)
assert m["parameters"]==[
    {"sequence":1,"name":"sort_param","metadata_type":"Int32[]","param_row_hex":"00000100ec510700","flags_raw":"0x0000"},
    {"sequence":2,"name":"sort_idx","metadata_type":"Int32[]","param_row_hex":"00000200f7510700","flags_raw":"0x0000"},
    {"sequence":3,"name":"asdes","metadata_type":"Int32","param_row_hex":"0000030000520700","flags_raw":"0x0000"},
    {"sequence":4,"name":"first","metadata_type":"Int32","param_row_hex":"0000040024100200","flags_raw":"0x0000"},
    {"sequence":5,"name":"last","metadata_type":"Int32","param_row_hex":"000005006cc80000","flags_raw":"0x0000"}
]
assert m["return_type"]=={"metadata_type":"Void"}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==(
    "0x0000","0x0096","fat","13300600c4000000d1060011",6,"0x110006D1"
)
assert (m["code_size"],m["code_sha256"])==(196,"14e7deca98e8fbf64b0564a069032b864cbea75e70eeabe0051e1091470c5718")
assert m["body_hex"]=="050a0e040b02060758185b940c043a2900000038040000000617580a020694083ff3ffffff38040000000717590b020794083df3ffffff382400000038040000000617580a020694083df3ffffff38040000000717590b020794083ff3ffffff06073f05000000382b0000000206940d030694130402060207949e03060307949e0207099e030711049e0617580a0717590b3876ffffff050617593c0c0000000203040506175928a14a00060e040717583e0d0000000203040717580e0428a14a00062a"

ls=s["dll"]["local_signature"]
assert (ls["token"],ls["standalone_sig_row_hex"],ls["blob_hex"])==("0x110006D1","9afc0100","07050808080808")
assert ls["locals"]==[
    {"index":0,"metadata_type":"Int32"},{"index":1,"metadata_type":"Int32"},
    {"index":2,"metadata_type":"Int32"},{"index":3,"metadata_type":"Int32"},{"index":4,"metadata_type":"Int32"}
]
assert s["dll"]["field_accesses"]==[]
calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["recursive"]) for x in calls]==[
    ("0x00A7","call","0x06004AA1",True),("0x00BE","call","0x06004AA1",True)
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="5dbc3db6e89d2cca543cf50d4aba38d0680d37055c36b11942d5130624eb2f44"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert len(refs)==21
assert len({x["caller_token"] for x in refs})==20
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="dadf2d5ce33ff219cc19f391ac05cc7499cc0983466534264f590ad22b4cb71f"
assert hashlib.sha256(("".join(x+"\n" for x in sorted({r["caller_token"] for r in refs}))).encode()).hexdigest()=="6e22fe6addfd2305992cadf1ee3f15508915bf2eac08a5da5d00cb88d8050b24"
assert [(x["caller_method"],x["call_il"]) for x in refs if x["caller_token"]=="0x06004AA1"]==[
    ("QuickSort_Int","0x00A7"),("QuickSort_Int","0x00BE")
]
assert [(x["caller_token"],x["caller_method"],x["call_il"]) for x in refs if x["caller_method"]=="Shuffle"]==[
    ("0x06004AA7","Shuffle","0x003B")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(21,20)
assert s["dll"]["normalized_reference_map_sha256"]=="dadf2d5ce33ff219cc19f391ac05cc7499cc0983466534264f590ad22b4cb71f"
assert s["dll"]["normalized_caller_token_set_sha256"]=="6e22fe6addfd2305992cadf1ee3f15508915bf2eac08a5da5d00cb88d8050b24"

c=s["capture_boundary"]
assert c["misc_quicksort_int_row_count"]==0
assert c["misc_shuffle_row_count"]==0
assert c["playercontroller_ai_make_rapid_push_tbl_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL MISC QUICKSORT INT SUMMARY: PASS")
