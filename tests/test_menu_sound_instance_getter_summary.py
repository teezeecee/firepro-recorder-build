#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_instance_getter.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_INSTANCE_GETTER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600527C","0x0032178B","000012aa14")
assert (m["code_size"],m["code_sha256"])==(6,"51403f7f590ffecc93a4904d8183a6255e36fdc173d7d24ad889577fbf035c03")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(2,0,0)
assert s["dll"]["field"]["token"]=="0x040086EA"
assert [x["call_il"] for x in s["dll"]["fact_0111_bridges"]]==["0x0074","0x008E"]
print("DLL MENU SOUND INSTANCE GETTER SUMMARY: PASS")
