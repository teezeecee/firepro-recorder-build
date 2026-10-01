#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"mymusic_check_file.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MYMUSIC_CHECK_FILE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06002C1E","0x001AE7A4",25,"193b347ba039064fe416b7d3c34758af6401a2ead6f5c45046904e0a29646877")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(8,1,2)
assert s["dll"]["exact_body"][0]["token"]=="0x04003903"
assert s["dll"]["exact_body"][2]["token"]=="0x0A000012"
assert s["dll"]["exact_body"][3]["token"]=="0x0A000216"
assert s["dll"]["direct_call_inventory"]["total_call_sites"]==7
assert s["dll"]["fact_0096_bridge"]["call_il"]=="0x0098"
print("DLL MYMUSIC CHECK FILE SUMMARY: PASS")
