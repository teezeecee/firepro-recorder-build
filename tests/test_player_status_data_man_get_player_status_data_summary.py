#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_status_data_man_get_player_status_data.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_STATUS_DATA_MAN_GET_PLAYER_STATUS_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06005074","0x00305440","405430000000960015440a0027d502000b3b","000112a82c11a828")
assert m["parameters"]==[{"sequence":1,"name":"st","metadata_type":"PlStateEnum","param_row_hex":"00000100c4bd0600","flags_raw":"0x0000"}]
assert (m["return_type_metadata"],m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"],m["locals"])==("PlayerStatusData","0x0000","0x0096","tiny","0x66",8,"0x00000000",[])
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(25,"3654b9b747fafe496cea44043ad40832a25d81f2537b71d46331b87e7bac4cb3","02163f08000000021f4a3f02000000142a7e6c620004029a2a")
assert s["dll"]["metadata_types"]==[
 {"role":"parameter","metadata_name":"PlStateEnum","typedef_rid":2570,"typedef_row_hex":"01010000207b000000000000450318627250","namespace":""},
 {"role":"return","metadata_name":"PlayerStatusData","typedef_rid":2571,"typedef_row_hex":"010010002c7b000000000000090364627250","namespace":""}]
assert s["dll"]["fields"]==[{"token":"0x0400626C","owner":"PlayerStatusDataMan","name":"PlayerStatusDataTbl","field_row_hex":"160020ff030001390000","signature_blob_hex":"061d12a82c","metadata_type":"PlayerStatusData[]"}]
fa=s["dll"]["field_accesses"]
assert fa==[{"il":"0x0011","opcode":"ldsfld","token":"0x0400626C"}]
assert hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="c9b51cc2f79b5c8e3f47fcecf675f1aa6d82027e2895d6f265ad17e47b07dfdc"
br=s["dll"]["branches"]
assert br==[{"il":"0x0002","opcode":"blt","target":"0x000F","raw_compare_rhs":0},{"il":"0x000A","opcode":"blt","target":"0x0011","raw_compare_rhs":74}]
assert hashlib.sha256(json.dumps(br,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="8a94d1d858e3f15daf52b688184e3ae0c5f1ac9a5e432f659e782ea295143b9a"
assert s["dll"]["canonical_internal_calls"]==[] and s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert len(refs)==16 and s["dll"]["direct_reference_count"]==16 and s["dll"]["direct_caller_method_count"]==16
assert s["dll"]["normalized_reference_map_sha256"]=="7f26ea4578d18ca3013fa11e1b82bbdf5fa8d65f1f13c5ccae1704c68870d544"
assert s["dll"]["normalized_caller_token_set_sha256"]=="d651bbe59276fdc0f99e12d13e8e0a18c3a45a50f93d1e5fdcc7c19596737d3a"
for k,v in s["capture_boundary"].items():
    if k.endswith("_row_count"): assert v==0
assert s["capture_boundary"]["promoted_as_evidence"] is False
sel=s["selection_boundary"]
assert sel["selected_leaf"]["code_size"]==25 and sel["selected_leaf"]["methoddef_child_count"]==0
assert sel["smaller_blocked_wrapper"]["code_size"]==15 and sel["smaller_blocked_wrapper"]["dependency_code_size"]==569
print("DLL PLAYER STATUS DATA MAN GET PLAYER STATUS DATA SUMMARY: PASS")
