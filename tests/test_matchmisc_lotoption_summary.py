#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"matchmisc_lotoption.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_MATCHMISC_LOTOPTION_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x0600495B","0x002B0230","30022b000000960095fb090089af01003636","0001081d08"
)
assert m["parameters"]==[
    {"sequence":1,"name":"rate_tbl","metadata_type":"Int32[]","param_row_hex":"000001006f4f0700","flags_raw":"0x0000"}
]
assert (m["return_type_metadata"],m["impl_flags_raw"],m["method_attributes_raw"])==("Int32","0x0000","0x0096")
assert (m["header_format"],m["fat_header_bytes_raw"],m["max_stack"],m["local_signature_token"])==(
    "fat","133003003400000073000011",3,"0x11000073"
)
assert (m["local_signature_row_hex"],m["local_signature_blob_hex"])==("755f0100","070408080808")
assert m["locals"]==[
    {"index":0,"metadata_type":"Int32"},{"index":1,"metadata_type":"Int32"},
    {"index":2,"metadata_type":"Int32"},{"index":3,"metadata_type":"Int32"}
]
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    52,"6d094b5b2ba805a275e1d97aa553088f42a9dbe4937cb83440b230ade378851f",
    "161f64287b4900060a028e690b160c160d381300000008020994580c06083c02000000092a0917580d09073fe6ffffff0717592a"
)
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(35,3,1)

calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"],x["raw_arguments"]) for x in calls]==[
    ("0x0003","call","0x0600497B","FACT-0032",[0,100])
]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="7f29a5a0588dcc84dee0116cdfa0835c9b4e05f281e4738922ef6f77024240b5"
assert s["dll"]["external_memberrefs"]==[]

refs=s["dll"]["direct_in_assembly_references"]
assert len(refs)==24
assert len({x["caller_token"] for x in refs})==15
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FE1","Process_Grapple_Front","0x0158","call"),
    ("0x06004FE3","Process_Grapple_BackAtk","0x00CB","call"),
    ("0x06004FE4","Process_Grapple","0x01A3","call"),
    ("0x06004FE4","Process_Grapple","0x0204","call"),
    ("0x06004FE4","Process_Grapple","0x024A","call"),
    ("0x06004FE4","Process_Grapple","0x0290","call"),
    ("0x06004FE7","Process_OnCorner","0x0109","call"),
    ("0x06004FEA","Process_OpponentDown_DownAttack","0x00B7","call"),
    ("0x06004FED","Process_OpponentDown_Dive","0x0093","call"),
    ("0x06004FED","Process_OpponentDown_Dive","0x00A5","call"),
    ("0x06004FEE","Process_OpponentDown_Dive_Stun","0x00A7","call"),
    ("0x06004FEE","Process_OpponentDown_Dive_Stun","0x00B9","call"),
    ("0x06004FEF","Process_OpponentDown_Center","0x0082","call"),
    ("0x06004FF0","Process_OpponentDown","0x009F","call"),
    ("0x06004FF1","Process_OpponentStands_OpponentOutOfRing","0x00BB","call"),
    ("0x06004FF1","Process_OpponentStands_OpponentOutOfRing","0x00E1","call"),
    ("0x06004FF2","Process_OpponentStands_AfterHammerThrow","0x0075","call"),
    ("0x06004FF3","Process_OpponentStands_LeanOnCorner","0x006F","call"),
    ("0x06004FF5","Process_OpponentStands_Stun","0x0045","call"),
    ("0x06004FF5","Process_OpponentStands_Stun","0x00CD","call"),
    ("0x06004FF5","Process_OpponentStands_Stun","0x0195","call"),
    ("0x06004FF6","Process_OpponentStands_Far","0x009B","call"),
    ("0x06004FF6","Process_OpponentStands_Far","0x0113","call"),
    ("0x06006ACE","GetGenerateWeaponKind","0x0007","call")
]
assert hashlib.sha256(json.dumps(refs,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="3e5bf66dd56899a8fe42ff08972f56478275e3887dca0a61848d99426fbac7cc"
callers=sorted({x["caller_token"] for x in refs},key=lambda x:int(x,16))
assert hashlib.sha256("".join(x+"\n" for x in callers).encode()).hexdigest()=="afa0d52d08d97e2072d7561b6bcbf3ea02737d28587f66785e8302a5cd14eb38"
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(24,15)

c=s["capture_boundary"]
assert c["matchmisc_lotoption_row_count"]==0
assert c["matchrandom_range_row_count"]==0
assert c["playercontroller_ai_process_opponent_stands_after_hammer_throw_row_count"]==0
assert c["promoted_as_evidence"] is False
print("DLL MATCHMISC LOTOPTION SUMMARY: PASS")
