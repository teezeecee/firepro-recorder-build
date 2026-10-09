#!/usr/bin/env python3
"""FACT-0263 stable source-boundary witness and canonical registry checks."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/"canonical/witnesses/CAP-R6-001/playercontroller_ai_move_to_dest_vector_wrapper.summary.json").read_text(encoding="utf-8"))
d=s["dll"];m=d["method"];reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_MOVE_TO_DEST_VECTOR_WRAPPER_V1"
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"],m["tiny_header_hex"])==("0x06004FDB","0x002F944B","4b942f0000008100113a0a000bcf0200ce3a","200111904c1131","56")
assert (m["parameter_count"],m["parameter_name"],m["parameter_row_hex"])==(1,"dest","0000010092ed0600")
assert m["body_hex"]=="020f017b5900000a0f017b5a00000a28dc4f00062a"
assert len(bytes.fromhex(m["body_hex"]))==m["code_size"]==21 and m["decoded_instruction_count"]==7
assert hashlib.sha256(bytes.fromhex(m["body_hex"])).hexdigest()==m["code_sha256"]=="11eb9cbb8fd8c2952d6bd659ac309e96e21f77918209a8584bae8cdc24e55c8e"
assert [(r["il"],r["opcode"]) for r in d["instructions"]]==[("0x0000","ldarg.0"),("0x0001","ldarga.s"),("0x0003","ldfld"),("0x0008","ldarga.s"),("0x000A","ldfld"),("0x000F","call"),("0x0014","ret")]
assert [(x["token"],x["name"]) for x in d["memberref_field_sites"]]==[("0x0A000059","x"),("0x0A00005A","y")]
assert d["memberref_field_site_count"]==2 and d["direct_methoddef_call_count"]==1 and d["branch_count"]==0
assert d["direct_methoddef_call_sites"]==[{"il":"0x000F","opcode":"call","token":"0x06004FDC","owner":"PlayerController_AI","name":"MoveToDest","callee_rva":"0x002F9464","callee_code_size":142,"callee_code_sha256":"3f9d8816c85afca89e72a9f2fbb744ecdb15ddc77d699383c096870921377526"}]
assert d["direct_in_assembly_references"]==[{"caller_type":"PlayerController_AI","caller_namespace":"","caller_method":"AIActFunc_RunAndFlyToOutOfRing","caller_token":"0x06004FBB","caller_rva":"0x002F7048","caller_code_size":381,"caller_code_sha256":"a9fef818ac551e87a8b4683539244329c2febaabb398d07764793733d426c676","call_il":"0x00F9","opcode":"call"}]
assert s["capture_boundary"]["checked_method_event_counts"]=={"PlayerController_AI.MoveToDest":0,"PlayerController_AI.AIActFunc_RunAndFlyToOutOfRing":0}
assert s["capture_boundary"]["promoted_as_evidence"] is False
assert (R/"canonical/facts/FACT-0263-playercontroller-ai-move-to-dest-vector-wrapper.json").exists()
assert sum(f["family_id"]==s["dataset_id"] for f in reg["families"])==1
assert len({f["family_id"] for f in reg["families"]})==len(reg["families"])
print("PLAYERCONTROLLER MOVE TO DEST WRAPPER SUMMARY: PASS")
