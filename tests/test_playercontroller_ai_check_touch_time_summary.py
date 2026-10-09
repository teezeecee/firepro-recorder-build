#!/usr/bin/env python3
"""FACT-0262: static source summary consistency; DLL/R6 bytes checked by verifier."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_check_touch_time.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"]
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_CHECK_TOUCH_TIME_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"],m["tiny_header_hex"])==("0x06005000","0x002FC1A0","a0c12f0000008100343d0a00db490000dc3a","200002","6a")
assert m["parameter_count"]==0 and m["body_hex"]=="027b4a6100047b3f600004027b706100043f02000000172a162a"
assert len(bytes.fromhex(m["body_hex"]))==m["code_size"]==26 and m["decoded_instruction_count"]==10
assert hashlib.sha256(bytes.fromhex(m["body_hex"])).hexdigest()==m["code_sha256"]=="ec0c4e18703199e422dda614cb0e1d9571c2848c7f95180f32bb8371dbd0a211"
assert [(x["il"],x["opcode"]) for x in d["instructions"]]==[("0x0000","ldarg.0"),("0x0001","ldfld"),("0x0006","ldfld"),("0x000B","ldarg.0"),("0x000C","ldfld"),("0x0011","bgt"),("0x0016","ldc.i4.1"),("0x0017","ret"),("0x0018","ldc.i4.0"),("0x0019","ret")]
assert d["branch_sites"]==[{"il":"0x0011","opcode":"bgt","relative_i32":2,"target_il":"0x0018"}] and d["branch_count"]==1
assert [(f["token"],f["name"]) for f in d["fields"]]==[("0x0400614A","PlObj"),("0x0400603F","hasRightFrm"),("0x04006170","touchFrm")]
assert d["field_site_count"]==3 and d["direct_methoddef_call_count"]==d["memberref_method_call_count"]==0
assert d["direct_in_assembly_references"]==[{"caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"Process_Touch","caller_token":"0x06005001","caller_rva":"0x002FC1BC","caller_code_size":832,"caller_code_sha256":"a09a556323cab95f9e04f3c232d05d6baa4bb404947df32710d62965890a267e","call_il":"0x0020","opcode":"call"}]
assert d["direct_reference_count"]==d["direct_caller_method_count"]==1
assert w["capture_boundary"]["checked_method_event_counts"]=={"PlayerController_AI.CheckTouch_Time":0,"PlayerController_AI.Process_Touch":0}
assert w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0262-playercontroller-ai-check-touch-time.json").exists()
print("PLAYERCONTROLLER AI CHECK TOUCH TIME SUMMARY: PASS")
