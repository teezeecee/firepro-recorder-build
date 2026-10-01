#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_play.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_PLAY_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052E7","row_hex":"805a32000000e601ac5a0600a4e502005d3d","rva":"0x00325A80"}
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052E7","0x00325A80","20010115118839011182c1")
assert (m["code_size"],m["code_sha256"])==(564,"25cfa99ab6e97f650b4e517fa419b12acb018df2aab2933a87b40953a7084a26")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"])==("0x001B",7,"0x11001220")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(177,23,37)
eh=s["dll"]["exception_section"]
assert (eh["size_bytes"],eh["sha256"])==(52,"f8df63a73e467352a3ef02ab450c1b90afb6379833275bb04e844ee0a95cd802")
assert [x["class_token"] for x in eh["clauses"]]==["0x010000C2","0x010000D2"]
assert [x["call_il"] for x in s["dll"]["fact_0133_bridges"]]==["0x00F6","0x01AD"]
print("DLL U AUDIO PLAY SUMMARY: PASS")
