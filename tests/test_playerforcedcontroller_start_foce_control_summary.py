#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playerforcedcontroller_start_foce_control.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERFORCEDCONTROLLER_START_FOCE_CONTROL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600503F","0x0030091A",29,"ede6d069634bd8695534188e0ff9ca8fb6cd7a4669425c39b4407cd7c3327320")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["header_format"],m["tiny_header_byte_raw"])==("1a093000000086006d400a008dcc0200ee3a","20010111a804","tiny","0x76")
assert s["dll"]["parameter_type"]["metadata_name"]=="ForceCtrlEnum" and s["dll"]["parameter_type"]["typedef_rid"]==2561
assert [(x["name"],x.get("raw_value"),x.get("source")) for x in s["dll"]["fields"]]==[("mode",None,"argument_1"),("step",0,None),("pauseByPrevPlayer",0,None),("isComplete",0,None)]
assert s["dll"]["internal_methoddef_calls"]==[]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["opcode_counts"]=={"call":0,"callvirt":1,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert s["dll"]["normalized_reference_map_sha256"]=="cc0833949bedc40f2bba43b0438d602a91dc8946b1e6e94a4568799712eafe25"
assert s["dll"]["normalized_caller_token_set_sha256"]=="18af17efd4c766049af7e0898bc6533726be47690a5d556c40b2397ac27d839a"
assert s["dll"]["direct_in_assembly_references"]==[{"caller_type":"Player","caller_namespace":"","caller_method":"Start_ForceControl","caller_token":"0x06004F74","caller_rva":"0x002F2E89","caller_code_size":20,"caller_code_sha256":"5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49","call_il":"0x000E","opcode":"callvirt"}]
c=s["capture_boundary"]
assert c["playerforcedcontroller_start_foce_control_row_count"]==0 and c["player_start_force_control_row_count"]==0 and c["playercontroller_tutorial_update_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_dependency_clean_parent"]
assert (n["token"],n["code_size"],n["canonical_child"]["fact_id"])==("0x06004F74",20,"FACT-0224")
print("DLL PLAYERFORCEDCONTROLLER START FOCE CONTROL SUMMARY: PASS")
