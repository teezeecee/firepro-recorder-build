#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_set_ai_act_stand_atk.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_STAND_ATK_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06004FA5","0x002F606E","6e602f000000810066350a00cbcd0200ba3a","20020111a7cc08")
assert m["parameters"]==[{"sequence":1,"name":"atk_kind","metadata_type":"StandAtkEnum","param_row_hex":"00000100976d0700","flags_raw":"0x0000"},{"sequence":2,"name":"tm","metadata_type":"Int32","param_row_hex":"00000200d7610700","flags_raw":"0x0000"}]
assert (m["return_type_metadata"],m["impl_flags_raw"],m["method_attributes_raw"],m["header_format"],m["tiny_header_byte_raw"],m["max_stack"],m["local_signature_token"],m["locals"])==("Void","0x0000","0x0081","tiny","0x46",8,"0x00000000",[])
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(17,"6cf419de21ddef2550f679f589ce58fe6b76a8b665220f170bc8a739fa93ef2f","021f1704289d4f000602037d4e6100042a")
assert s["dll"]["parameter_types"][0]=={"sequence":1,"metadata_name":"StandAtkEnum","typedef_rid":2547,"typedef_row_hex":"0301000086790000000000004503a2612d50","namespace":""}
assert s["dll"]["fields"]==[{"token":"0x0400614E","owner":"PlayerController_AI","name":"aiActPrm","field_row_hex":"0100dbf2030001000000","signature_blob_hex":"0608","metadata_type":"Int32"}]
fa=s["dll"]["field_accesses"]; assert [(x["il"],x["opcode"],x["token"]) for x in fa]==[("0x000B","stfld","0x0400614E")]
core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in fa]
assert hashlib.sha256(json.dumps(core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="d5718d050bd7e511e13bf4a3689b08e71f09a2eb9147f8bf1ef35f45a30e95ca"
calls=s["dll"]["canonical_internal_calls"]; assert [(x["il"],x["opcode"],x["token"],x["fact_id"],x["raw_argument_1"],x["argument_2_source"]) for x in calls]==[("0x0004","call","0x06004F9D","FACT-0043",23,"argument_2")]
call_core=[{"il":x["il"],"opcode":x["opcode"],"token":x["token"]} for x in calls]
assert hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(",",":")).encode()).hexdigest()=="50353803322a8a677c90ee71b786cfc1ce6d91e5b879abd11fb8eedc3e1f0c3b"
assert s["dll"]["external_memberrefs"]==[]
refs=s["dll"]["direct_in_assembly_references"]
assert [(x["caller_token"],x["caller_method"],x["call_il"],x["opcode"]) for x in refs]==[
("0x06004FCD","vpc_wait2","0x008B","call"),
("0x06004FF5","Process_OpponentStands_Stun","0x014C","call"),("0x06004FF5","Process_OpponentStands_Stun","0x01E3","call"),("0x06004FF5","Process_OpponentStands_Stun","0x01F1","call"),("0x06004FF5","Process_OpponentStands_Stun","0x01FF","call"),
("0x06004FF6","Process_OpponentStands_Far","0x0105","call"),("0x06004FF6","Process_OpponentStands_Far","0x0224","call"),
("0x06004FFA","Process_OpponentStands","0x007D","call"),("0x06004FFA","Process_OpponentStands","0x00CF","call"),("0x06004FFA","Process_OpponentStands","0x0110","call"),
("0x0600500E","Process_Second","0x0277","call")]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(11,5)
assert s["dll"]["normalized_reference_map_sha256"]=="728ef6545f9a114d98ea24ad7e20b2e22c9a29d494c187596f035415678f8f38"
assert s["dll"]["normalized_caller_token_set_sha256"]=="00401fd225d658d3e6e796b6a8fbd79090c46d0544edb505dde81f55bd6d5124"
for k,v in s["capture_boundary"].items():
    if k.endswith("_row_count"): assert v==0
assert s["capture_boundary"]["promoted_as_evidence"] is False
sel=s["selection_boundary"]
assert sel["smaller_blocked_wrapper"]["code_size"]==15 and sel["smaller_blocked_wrapper"]["dependency_code_size"]==569
assert sel["equal_size_alternative"]["token"]=="0x06004FA9" and sel["equal_size_alternative"]["code_size"]==17
assert sel["tie_break_rule"]=="equal code size -> lower MethodDef token"
assert sel["selected_leaf"]["token"]=="0x06004FA5" and sel["selected_leaf"]["canonical_child_fact_id"]=="FACT-0043"
print("DLL PLAYERCONTROLLER AI SET AI ACT STAND ATK SUMMARY: PASS")
