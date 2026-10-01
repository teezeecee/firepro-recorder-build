#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"save_data_edit_wrestler_index.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SAVE_DATA_EDIT_WRESTLER_INDEX_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060051B5","0x00316558","2001081187b8")
assert (m["code_size"],m["code_sha256"])==(68,"d3a61b6659b558132c7269733dda2c9925958fc65d6a5925f84474e04d42969d")
assert m["parameters"]==[{"sequence":1,"name":"wid","type":"WrestlerID"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(28,4,2)
assert s["dll"]["raw_gate"]["raw_value"]==10000
assert s["dll"]["scan"]["data_field"]["token"]=="0x040064F5"
assert s["dll"]["scan"]["element_id_field"]["token"]=="0x040010BD"
assert s["dll"]["scan"]["list_memberrefs"]["get_Item"]["token"]=="0x0A0007A3"
assert s["dll"]["scan"]["list_memberrefs"]["get_Count"]["token"]=="0x0A0007A4"
assert s["dll"]["fact_0102_bridge"]["call_il"]=="0x0002"
print("DLL SAVE DATA EDIT WRESTLER INDEX SUMMARY: PASS")
