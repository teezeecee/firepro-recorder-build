#!/usr/bin/env python3
"""Static witness checks; original source byte replay is a separate verifier."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_do_nothing.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"]
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_AI_ACT_FUNC_DO_NOTHING_V1"
assert w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["tiny_header_hex"],m["signature_blob_hex"])==("0x06004FAE","0x002F6117","17612f000000810027360a00db490000c93a","0a","200002")
assert (m["body_hex"],m["code_size"],m["decoded_instruction_count"])==("162a",2,2)
assert hashlib.sha256(bytes.fromhex(m["body_hex"])).hexdigest()==m["code_sha256"]=="84a0936ff1fba6d2811d094757231685673447aed2170738872305076026a316"
assert d["instructions"]==[{"il":"0x0000","opcode":"ldc.i4.0"},{"il":"0x0001","opcode":"ret"}]
assert (d["field_access_count"],d["direct_methoddef_call_count"],d["memberref_method_call_count"],d["branch_count"])==(0,0,0,0)
assert len(d["direct_in_assembly_references"])==d["direct_reference_count"]==d["direct_caller_method_count"]==1
ref=d["direct_in_assembly_references"][0]
assert (ref["caller_type"],ref["caller_method"],ref["caller_token"],ref["opcode"],ref["call_il"])==("PlayerController_AI","Init","0x06004F99","ldftn","0x0023")
assert w["capture_boundary"]["checked_names_event_row_count"]==0 and w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0260-playercontroller-ai-do-nothing.json").exists()
print("PLAYERCONTROLLER AI DO NOTHING SUMMARY: PASS")
