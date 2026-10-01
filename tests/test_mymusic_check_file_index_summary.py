#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"mymusic_check_file_index.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MYMUSIC_CHECK_FILE_INDEX_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06002C20","0x001AE7D8","00010208")
assert (m["code_size"],m["code_sha256"])==(73,"66362426cdc7c33b609dc94d3bb31cac438d725c0dc823789587063ab0174c7b")
assert m["parameters"]==[{"sequence":1,"name":"index","type":"Int32"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(23,3,4)
assert m["local_signature_token"]=="0x11000A75"
assert s["dll"]["fields"]["file_list_match"]["token"]=="0x04003905"
assert s["dll"]["fields"]["entry_name"]["token"]=="0x04003900"
assert s["dll"]["list_memberrefs"]["get_Count"]["token"]=="0x0A0008E9"
assert s["dll"]["list_memberrefs"]["get_Item"]["token"]=="0x0A0008EA"
assert s["dll"]["fact_0100_bridge"]["call_il"]=="0x0043"
print("DLL MYMUSIC CHECK FILE INDEX SUMMARY: PASS")
