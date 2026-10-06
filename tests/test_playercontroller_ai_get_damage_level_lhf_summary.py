#!/usr/bin/env python3
import hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_get_damage_level_lhf.summary.json").read_text(encoding="utf-8"))

assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_GET_DAMAGE_LEVEL_LHF_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==(
    "0x06004F9C","0x002F5F14","145f2f0000009100b2340a0096cd0200a83a","000111a7c80c"
)
assert m["parameters"]==[{"sequence":1,"name":"hp","metadata_type":"Float32","param_row_hex":"000001003caa0100"}]
assert m["return_type"]=={
    "kind":"ValueType","metadata_type":"DamageLevelEnum_LHF","typedef_rid":2546,
    "typedef_row_hex":"03010000727900000000000045039e612d50","namespace":""
}
assert (m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["init_locals"],m["local_signature_token"])==(
    "0x0000","0x0091","fat","13300300310000001f000011",3,True,"0x1100001F"
)
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(
    49,"b4eb2ae2869d79032fa0ad8a1ed654496300f2fed1cc8736cdb82f037c089329",
    "0228754900060a067e380d00047b3a0d000416984402000000162a067e380d00047b3a0d000417984402000000172a182a"
)
assert (m["instruction_count"],m["field_access_count"],m["branch_instruction_count"],m["methoddef_call_site_count"],m["memberref_method_call_count"])==(21,4,2,1,0)
ls=s["dll"]["local_signature"]
assert (ls["token"],ls["standalone_sig_row_hex"],ls["blob_hex"],ls["locals"])==(
    "0x1100001F","a8590100","07010c",[{"index":0,"metadata_type":"Float32"}]
)
assert [(x["token"],x["owner"],x["name"],x["field_row_hex"],x["signature_blob_hex"]) for x in s["dll"]["fields"]]==[
    ("0x04000D38","COMLevelDataManager","inst","1600062201007d0a0000","06128638"),
    ("0x04000D3A","COMLevelDataManager","damageLevelThreshold_LHF","0600553e0100a7020000","061d0c")
]
fa=s["dll"]["field_accesses"]
assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[
    ("0x0008","ldsfld","0x04000D38"),("0x000D","ldfld","0x04000D3A"),
    ("0x001C","ldsfld","0x04000D38"),("0x0021","ldfld","0x04000D3A")
]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="ba5bd824c6362063a086eddb054ebfdc3bf47338c261b80157d07b3b02bdd3c4"
calls=s["dll"]["canonical_internal_calls"]
assert [(x["il"],x["opcode"],x["token"],x["fact_id"]) for x in calls]==[
    ("0x0001","call","0x06004975","FACT-0031")
]
call_core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="b87deb45729697e188e61d504a1c624647acae90f54c60caa88f0f2593b37d70"
assert s["dll"]["external_memberref_method_calls"]==[]
bm=s["dll"]["branch_map"]
assert bm==[
    {"il":"0x0014","opcode":"blt.un","target":"0x001B"},
    {"il":"0x0028","opcode":"blt.un","target":"0x002F"}
]
assert hashlib.sha256(json.dumps(bm,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="9655d77aabe239d7d5c59d2d4c61dc3ce6e56b3e648112502717e1436045c229"
assert s["dll"]["raw_returns"]==[0,1,2]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
    ("0x06004FEA","Process_OpponentDown_DownAttack","0x0040","call"),
    ("0x06004FED","Process_OpponentDown_Dive","0x007D","call"),
    ("0x06004FEE","Process_OpponentDown_Dive_Stun","0x008F","call"),
    ("0x06004FF5","Process_OpponentStands_Stun","0x015F","call"),
    ("0x0600500F","CheckOverTheTopRope","0x0053","call")
]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(5,5)
assert s["dll"]["normalized_reference_map_sha256"]=="55742080af9dbdefe43d7a5664854d641b0c8d7df250f3e1f1307c32b8195403"
assert s["dll"]["normalized_caller_token_set_sha256"]=="b0c8a1ab8a339ba9d344c9781a3389709e20acd5fd61bd8d6628b97c3ff63867"
c=s["capture_boundary"]
for k,v in c.items():
    if k.endswith("_row_count"): assert v==0
assert c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER AI GET DAMAGE LEVEL LHF SUMMARY: PASS")
