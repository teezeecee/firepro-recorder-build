#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_tutorial_process_grapple.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_TUTORIAL_PROCESS_GRAPPLE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600503C","0x00300718",109,"0e53fcf88961297caf1853917b18bd92786b40b340e2b81da12b5f1ac4447c54")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["header_format"],m["fat_header_hex"],m["max_stack"],m["local_signature_token"])==("1807300000008100bc3a0a005c480000ed3a","200001","fat","133003006d00000000000000",3,"0x00000000")
assert [(x["token"],x["owner"],x["name"]) for x in s["dll"]["fields"]]==[
("0x040061C8","PlayerController_Tutorial","plObj"),("0x04005FB7","Player","State"),("0x040061C9","PlayerController_Tutorial","atkWaitTimer"),("0x04005FFF","Player","penaltyTime"),
("0x04005FA8","Player","animator"),("0x04005EE7","FormAnimator","isAnmPause"),("0x04006118","PlayerController","padPush"),("0x04006117","PlayerController","padOn")]
assert s["dll"]["normalized_field_access_map_sha256"]=="60a8bde3cf4c9c0d9d8dcf16bb7a757c0d56a85ceffa55acbabb221c6cf84303"
assert s["dll"]["internal_methoddef_calls"]==[]
assert (s["dll"]["direct_reference_count"],s["dll"]["direct_caller_method_count"])==(1,1)
assert s["dll"]["opcode_counts"]=={"call":1,"callvirt":0,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert s["dll"]["normalized_reference_map_sha256"]=="d72bb74bca1d8cfd7f8f5dc147961879cb4a3712df3bc65d5c53895c0d22ef71"
assert s["dll"]["normalized_caller_token_set_sha256"]=="43e28eea2cc7a60d5d07a84a1817375e230d7747eab89d02b1f76f54efacd7a6"
assert s["dll"]["direct_in_assembly_references"]==[{"caller_type":"PlayerController_Tutorial","caller_namespace":"","caller_method":"Update","caller_token":"0x0600503D","caller_rva":"0x00300794","caller_code_size":352,"caller_code_sha256":"ee9742c42475c1d0a1ab0513f2cab8c4e25b5f3d3e10b750adf9ecd498573bbe","call_il":"0x010B","opcode":"call"}]
assert [(x["il"],x["opcode"],x.get("compare_raw_value"),x["target_il"]) for x in s["dll"]["branch_sites"] if x["opcode"]!="brtrue"]==[("0x000D","beq",22,"0x001A"),("0x0026","ble",0,"0x002C"),("0x0057","ble",0,"0x005D")]
assert [(x["field"],x.get("raw_value")) for x in s["dll"]["raw_writes"] if "raw_value" in x]==[("PlayerController_Tutorial.atkWaitTimer",6),("PlayerController.padPush",16),("PlayerController.padOn",1)]
c=s["capture_boundary"]
assert c["playercontroller_tutorial_process_grapple_row_count"]==0 and c["playercontroller_tutorial_update_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_dependency_clean_parent"]
assert (n["token"],n["code_size"],n["internal_methoddef_reference_count"],n["unique_internal_methoddef_callee_count"],n["all_internal_methoddef_callees_canonical_after_this_fact"])==("0x0600503D",352,5,4,True)
assert [x["fact_id"] for x in n["internal_methoddef_references"]]==["FACT-0225","FACT-0223","FACT-0226","FACT-0025","FACT-0025"]
print("DLL PLAYERCONTROLLER TUTORIAL PROCESS GRAPPLE SUMMARY: PASS")
