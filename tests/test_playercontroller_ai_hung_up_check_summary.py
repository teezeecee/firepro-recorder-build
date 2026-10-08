#!/usr/bin/env python3
"""Static canonical witness regression for FACT-0255; raw file validation uses the separate prover."""
import hashlib,json,struct
from pathlib import Path
root=Path(__file__).resolve().parents[1]
w=json.loads((root/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_ai_hung_up_check.summary.json").read_text(encoding="utf-8"))
def dig(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(",",":")).encode()).hexdigest()
assert w["schema_version"]==1 and w["source_ids"]==["DLL-001"]
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_HUNG_UP_CHECK_V1"
d=w["dll"];m=d["method"]
assert d["sha256"]=="9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6"
assert d["size_bytes"]==8171008
assert (m["owner"],m["name"],m["token"],m["rva"])==("PlayerController_AI","HungUpCheck","0x06004FD9","0x002F91E4")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["fat_header_hex"])==("e4912f0000008100f7390a00db490000ce3a","200002","13300300fa00000009110011")
assert (m["local_signature_token"],m["local_signature_row_hex"],m["local_signature_blob_hex"],m["max_stack"],m["parameter_count"])==("0x11001109","37cf0200","070412a82c1131081131",3,0)
body=bytes.fromhex(m["body_hex"])
assert len(body)==m["code_size"]==250 and m["decoded_instruction_count"]==89
assert hashlib.sha256(body).hexdigest()==m["code_sha256"]=="bd6e95d91e9c741be24e1cd719aa40f61488fd454e77e8003688abb237bb2106"
assert len(d["fields"])==8 and len(d["field_accesses"])==19
assert dig(d["field_accesses"])==d["field_accesses_digest"]=="1ba344c5862683c55db1f19c246a4f33d52a32d94d8f06ca96a376cf6f8add74"
assert len(d["memberref_calls"])==6
assert sorted(x["token"] for x in d["memberref_calls"])==sorted(["0x0A000089","0x0A00008B","0x0A00008E","0x0A00054E","0x0A000100","0x0A000091"])
assert len(d["calls"])==9 and dig(d["calls"])==d["calls_digest"]=="b40b9b622d11c51cfe98ac9eef5d4126f099de7cb362062ba5f2a031c3268f4c"
assert len(d["branches"])==6 and dig(d["branches"])==d["branches_digest"]=="00e7461af0b32f93d5e25432bb4f3ca1349cb1456a4bdbc833daf49bb607f1d8"
assert [(x["il"],x["token"]) for x in d["canonical_internal_calls"]]==[("0x000B","0x06005074"),("0x002D","0x06004FD8")]
assert [x["canonical_fact_id"] for x in d["canonical_internal_calls"]]==["FACT-0253","FACT-0038"]
refs=d["direct_in_assembly_references"]
assert len(refs)==d["direct_reference_count"]==d["direct_caller_method_count"]==5
assert [(x["caller_token"],x["call_il"]) for x in refs]==[("0x06004FB0","0x00F4"),("0x06004FB1","0x00D5"),("0x06004FC1","0x0203"),("0x06004FC4","0x0074"),("0x06004FC5","0x02C1")]
assert dig(refs)==d["direct_reference_digest"]=="e2896d3eae44da9e8dafa281f3d7062add43367154c0a2cbd9d86cd6eeb2b2a4"
assert hashlib.sha256(("\n".join(sorted({x["caller_token"] for x in refs}))+"\n").encode()).hexdigest()==d["caller_token_set_digest"]=="f99adb0c84c2ab38c178c86d7be78b924e6f9f05a1ff43de92854a5b4e01f6e0"
assert body[0xC3:0xC8]==bytes.fromhex("2200000041")
assert body[0xEC:0xF1]==bytes.fromhex("220ad7a33c")
assert w["capture_boundary"]["event_trace_sha256"]=="79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd"
assert w["capture_boundary"]["method_and_direct_callers_row_count"]==0
assert w["capture_boundary"]["promoted_as_evidence"] is False
assert (root/"canonical"/"facts"/"FACT-0255-playercontroller-ai-hung-up-check.json").is_file()
print("DLL PLAYERCONTROLLER AI HUNG UP CHECK SUMMARY: PASS")
