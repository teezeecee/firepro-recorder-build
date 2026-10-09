#!/usr/bin/env python3
"""Static metadata/witness integrity for FACT-0258; original source replay is separate."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_front_grapple.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"];body=bytes.fromhex(m["body_hex"])
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_FRONT_GRAPPLE_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06004FB0","0x002F6234","34622f00000081004f360a00db490000c93a","200002")
assert (m["fat_header_hex"],m["local_signature_token"],m["local_signature_row_hex"],m["local_signature_blob_hex"])==("133004000a010000f2100011","0x110010F2","f3cd0200","070211a7dc12a788")
assert len(body)==m["code_size"]==266 and hashlib.sha256(body).hexdigest()==m["code_sha256"]=="fe0478463f631f1ff67e0445960fb13a4d4e7b436d2a261f50716bb116f6ba3f"
assert len(d["instructions"])==m["decoded_instruction_count"]==80 and len(d["branches"])==11 and len(d["fields"])==22
assert len(d["direct_methoddef_calls"])==7 and d["memberref_method_call_count"]==0
assert [(c["token"],c["canonical_fact_id"]) for c in d["direct_methoddef_calls"]]==[
("0x06004FD7","FACT-0254"),("0x06005065","FACT-0109"),("0x06004966","FACT-0088"),("0x06004975","FACT-0031"),("0x06004FAD","FACT-0044"),("0x06004FD9","FACT-0255"),("0x06004F9E","FACT-0256")]
assert len(d["direct_in_assembly_references"])==d["direct_reference_count"]==1
assert (d["direct_in_assembly_references"][0]["caller_method"],d["direct_in_assembly_references"][0]["opcode"],d["direct_in_assembly_references"][0]["call_il"])==("Init","ldftn","0x004B")
assert all(c["operand"] in {i["il"] for i in d["instructions"]} for c in d["branches"])
assert w["capture_boundary"]["checked_names_event_row_count"]==0 and w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0258-playercontroller-ai-go-front-grapple.json").exists()
print("PLAYERCONTROLLER AI GO FRONT GRAPPLE SUMMARY: PASS")
