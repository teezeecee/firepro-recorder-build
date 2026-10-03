#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_start_force_control.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_START_FORCE_CONTROL_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004F74","0x002F2E89",20,"5f7e39e4415fbe3bb7d6ddf30d6f7eceda02db18649b443d4f44f0a07a291d49")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["header_format"],m["tiny_header_byte_raw"])==("892e2f0000008600f9320a008dcc0200913a","20010111a804","tiny","0x52")
assert s["dll"]["parameter_type"]["metadata_name"]=="ForceCtrlEnum" and s["dll"]["parameter_type"]["typedef_rid"]==2561
assert [(x["name"],x.get("write_il"),x.get("load_il"),x.get("source")) for x in s["dll"]["fields"]]==[("forceControl","0x0002",None,"argument_1"),("plForcedController",None,"0x0009",None)]
assert s["dll"]["internal_methoddef_calls"]==[{"fact_id":"FACT-0224","callee_type":"PlayerForcedController","callee_method":"Start_FoceControl","callee_token":"0x0600503F","call_il":"0x000E","opcode":"callvirt","argument_source":"argument_1"}]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(18,15)
assert s["dll"]["opcode_counts"]=={"call":2,"callvirt":16,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert s["dll"]["normalized_reference_map_sha256"]=="44ad08326b234ca5a8d5a921fad79c66a37ed5cc4a82adb1e3f61147a399b402"
assert s["dll"]["normalized_caller_token_set_sha256"]=="75fe7eae110dd770f572eb87d17cb99ef25cd0a75f70c5cb32d74572ab81a024"
assert [x["caller_token"] for x in s["dll"]["direct_in_assembly_references"]].count("0x0600503D")==1
assert [x["call_il"] for x in s["dll"]["direct_in_assembly_references"] if x["caller_token"]=="0x0600503D"]==["0x0025"]
c=s["capture_boundary"]
assert c["player_start_force_control_row_count"]==0 and c["playerforcedcontroller_start_foce_control_row_count"]==0 and c["playercontroller_tutorial_update_row_count"]==0 and c["playercontroller_tutorial_process_grapple_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_dependency_clean_child"]
assert (n["token"],n["code_size"],n["internal_methoddef_call_count"],n["tutorial_call_il"])==("0x0600503C",109,0,"0x010B")
print("DLL PLAYER START FORCE CONTROL SUMMARY: PASS")
