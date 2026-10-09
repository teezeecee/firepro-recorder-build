#!/usr/bin/env python3
"""Static FACT-0261 witness checks; raw bytes checked by separate prover."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/playercontroller_ai_set_ai_act_counter_duration_write.summary.json").read_text(encoding="utf-8"))
d=w["dll"];m=d["method"]
assert w["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER_DURATION_WRITE_REFERENCES_V1" and w["source_ids"]==["DLL-001"]
assert (m["token"],m["rva"],m["methoddef_row_hex"],m["signature_blob_hex"],m["tiny_header_hex"])==("0x06004FAC","0x002F60EC","ec602f00000086000e360a009f490000c83a","20010108","22")
assert (m["parameter_count"],m["parameter_name"],m["parameter_row_hex"])==(1,"cnt","00000100f31d0700")
assert (m["body_hex"],m["code_size"],m["decoded_instruction_count"])==("02037d4c6100042a",8,4)
assert hashlib.sha256(bytes.fromhex(m["body_hex"])).hexdigest()==m["code_sha256"]=="cff3981d35f0878efae84ea0b7f25c9c403437bc3e9413041ba509fbb361fa1a"
assert d["instructions"]==[{"il":"0x0000","opcode":"ldarg.0"},{"il":"0x0001","opcode":"ldarg.1"},{"il":"0x0002","opcode":"stfld","operand":"0x0400614C"},{"il":"0x0007","opcode":"ret"}]
assert d["fields"]==[{"il":"0x0002","opcode":"stfld","token":"0x0400614C","owner":"PlayerController_AI","name":"aiActDuration","raw_row_hex":"0600c3f2030001000000","signature_blob_hex":"0608"}]
assert (d["branch_count"],d["direct_methoddef_call_count"],d["memberref_method_call_count"])==(0,0,0)
assert len(d["direct_in_assembly_references"])==d["direct_reference_count"]==4 and d["direct_caller_method_count"]==3
assert [(r["caller_method"],r["call_il"],r["opcode"]) for r in d["direct_in_assembly_references"]]==[("TestAI_Weapon","0x006A","callvirt"),("PlayAnimationSE","0x00FA","callvirt"),("SetAIAct","0x000E","call"),("SetAIAct","0x001D","call")]
assert w["capture_boundary"]["checked_method_event_counts"]=={"PlayerController_AI.SetAIActCounter":0,"PlayerController_AI.SetAIAct":0,"MatchDebug.TestAI_Weapon":0,"FormAnimator.PlayAnimationSE":90916}
assert w["capture_boundary"]["promoted_as_evidence"] is False
assert (ROOT/"canonical/facts/FACT-0261-playercontroller-ai-set-ai-act-counter.json").exists()
print("PLAYERCONTROLLER AI SET AI ACT COUNTER SUMMARY: PASS")
