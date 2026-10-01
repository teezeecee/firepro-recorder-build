#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_pause.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_PAUSE_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052E9","row_hex":"5c5d32000000e601d08703005c4800005f3d","rva":"0x00325D5C"}
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052E9","0x00325D5C","200001")
assert (m["code_size"],m["code_sha256"])==(134,"ea2a9629b5485ae8d47eb7166281fc0aefd20bdc8afde51a4830684d7b2406b2")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(42,9,8)
assert s["dll"]["direct_calls"]["get_send_playback_state"]["call_ils"]==["0x001F","0x002A","0x0064","0x006F"]
assert s["dll"]["member_calls"]["audio_source_pause"]["token"]=="0x0A000CE6"
assert s["dll"]["member_calls"]["audio_source_unpause"]["token"]=="0x0A000CE8"
eh=s["dll"]["exception_section"]
assert (eh["size_bytes"],eh["sha256"])==(28,"0182f6491b3e983aabf2cb42bc944c69f2225479a4b5464015a352ed7a895218")
assert [(x["try_offset"],x["handler_offset"],x["class_token"]) for x in eh["clauses"]]==[("0x001E","0x003A","0x010000C2"),("0x0063","0x007F","0x010000C2")]
assert s["dll"]["fact_0140_bridge"]["call_il"]=="0x0019"
print("DLL U AUDIO PAUSE SUMMARY: PASS")
