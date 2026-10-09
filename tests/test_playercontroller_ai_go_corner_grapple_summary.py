#!/usr/bin/env python3
"""Static witness closure for FACT-0259; raw source replay is separate."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_go_corner_grapple.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"];body=bytes.fromhex(m["body_hex"])
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_GO_CORNER_GRAPPLE_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"])==("0x06004FB2","0x002F6444","44642f000000810080360a00db490000c93a","200002")
assert (m["fat_header_hex"],m["local_signature_token"],m["local_signature_row_hex"],m["local_signature_blob_hex"])==("13300200360000008e020011","0x1100028E","6b940100","070112a788")
assert len(body)==m["code_size"]==54 and hashlib.sha256(body).hexdigest()==m["code_sha256"]=="3d9416da2398348a2eb7fd294fb81c3c87c1b39f9599a76eda4305b1bd80513d"
assert len(d["instructions"])==m["decoded_instruction_count"]==17 and len(d["branches"])==1 and len(d["fields"])==5
assert d["branches"]==[dict(il="0x0029",opcode="beq",operand="0x0034")]
assert len(d["direct_methoddef_calls"])==2 and d["memberref_method_call_count"]==0
assert [(c["token"],c["canonical_fact_id"]) for c in d["direct_methoddef_calls"]]==[("0x06005065","FACT-0109"),("0x06004FAD","FACT-0044")]
assert len(d["direct_in_assembly_references"])==d["direct_reference_count"]==d["direct_caller_method_count"]==1
assert (d["direct_in_assembly_references"][0]["caller_method"],d["direct_in_assembly_references"][0]["opcode"],d["direct_in_assembly_references"][0]["call_il"])==("Init","ldftn","0x005F")
assert all(x["operand"] in {i["il"] for i in d["instructions"]} for x in d["branches"])
assert len(w["capture_boundary"]["checked_method_names"])==3 and w["capture_boundary"]["checked_names_event_row_count"]==0 and w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0259-playercontroller-ai-go-corner-grapple.json").exists()
print("PLAYERCONTROLLER AI GO CORNER GRAPPLE SUMMARY: PASS")
