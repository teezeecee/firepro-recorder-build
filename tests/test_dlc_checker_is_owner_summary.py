#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"dlc_checker_is_owner.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_DLC_CHECKER_IS_OWNER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06001033","0x0005F7DC","0001021185c8")
assert (m["code_size"],m["code_sha256"])==(39,"1aef92c709ae4ad954e979dec831bd361ef6546059f6ddf914fe9fa352bae5cc")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"])==("0x001B",2,"0x110002A5")
assert m["local_signature_blob_hex"]=="07041185d01186590202"
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(16,2,3)
eh=s["dll"]["exception_section"]["clause"]
assert (eh["try_offset"],eh["try_length"],eh["handler_offset"],eh["handler_length"],eh["class_token"])==("0x000F",14,"0x001D",8,"0x010000C2")
assert eh["class_resolved"]=="System.Object"
assert s["dll"]["fact_0119_bridge"]["call_il"]=="0x0001"
print("DLL DLC CHECKER IS OWNER SUMMARY: PASS")
