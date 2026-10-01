#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_song_end.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SONG_END_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052E6","0x003259C8","200001")
assert (m["code_size"],m["code_sha256"])==(141,"3ff6f18fdb7ed86c92f309f6496f6d7fc3a7cee75b55c9174345fac0efaeee4c")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"])==("0x001B",2,"0x00000000")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(45,5,9)
assert s["dll"]["user_string"]["value"]=="Song end #7cgf87dcf7sd8csd"
clauses=s["dll"]["exception_section"]["clauses"]
assert len(clauses)==2
assert (clauses[0]["try_offset"],clauses[0]["try_length"],clauses[0]["handler_offset"],clauses[0]["handler_length"])==("0x0059",28,"0x0075",6)
assert (clauses[1]["try_offset"],clauses[1]["try_length"],clauses[1]["handler_offset"],clauses[1]["handler_length"])==("0x0000",128,"0x0080",12)
assert all(x["class_token"]=="0x010000C2" and x["class_resolved"]=="System.Object" for x in clauses)
assert s["dll"]["fact_0124_bridge"]["call_il"]=="0x0001"
print("DLL U AUDIO SONG END SUMMARY: PASS")
