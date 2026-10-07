#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_is_target_stunned.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_IS_TARGET_STUNNED_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06004FF4","0x002FB590","90b52f0000008100443c0a00db490000d93a","200002")
assert m["parameters"]==[] and m["return_type_metadata"]=="Boolean"
assert (m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==("fat","13300200640000008e020011",2,"0x1100028E")
assert m["local_signature_row_hex"]=="6b940100" and m["local_signature_blob_hex"]=="070112a788"
assert m["locals"]==[{"index":0,"metadata_type":"Player","typedef_rid":2530,"typedef_row_hex":"01001000fd480000000000005500565fa74e","namespace":""}]
assert (m["code_size"],m["code_sha256"])==(100,"6be0ad496b10e6b013a20cf29ce0fa8f50b2c835aad2392dee083cfedca721e0")
fa=s["dll"]["field_accesses"]; core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="75d9689017fbad25ea3b1958f2f042e804b4c82925057ff5a82c208dbd6903b7"
assert [(x["il"],x["opcode"],x["target"]) for x in s["dll"]["branches"]]==[("0x001E","bne.un","0x0025"),("0x0035","bge.un","0x003C"),("0x0044","bne.un","0x0062"),("0x004F","brfalse","0x0062"),("0x005B","ble","0x0062")]
c=s["dll"]["canonical_internal_calls"]; cc=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in c]
assert [(x["token"],x["fact_id"],x["code_size"]) for x in c]==[("0x06005065","FACT-0109",25),("0x06004975","FACT-0031",16)]
assert hashlib.sha256(json.dumps(cc,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="e5884ecbd4e1dad1e85c32298bef1b0c1f9126898265dd2d18cb959082a2f7e1"
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[("0x06004FB1","AIActFunc_GoBackGrapple","0x0017","call"),("0x06004FF5","Process_OpponentStands_Stun","0x0033","call")]
assert s["dll"]["normalized_reference_map_sha256"]=="3f47cd3c35c7650d8eefd0257ecac6fbfe42a0bbe93de424d53d09031c12c70e"
assert s["dll"]["normalized_caller_token_set_sha256"]=="3376d25c6c7dc91627ba537f75e795eedc2f074cb2fd9a18e2214dcc818c3e8e"
for k,v in s["capture_boundary"].items():
    if k.endswith("_row_count"): assert v==0
assert s["capture_boundary"]["promoted_as_evidence"] is False
sel=s["selection_boundary"]
assert sel["smaller_blocked_wrapper"]["code_size"]==15 and sel["smaller_blocked_wrapper"]["dependency_code_size"]==569
assert sel["selected_leaf"]["canonical_child_fact_ids"]==["FACT-0109","FACT-0031"]
print("DLL PLAYERCONTROLLER AI IS TARGET STUNNED SUMMARY: PASS")
