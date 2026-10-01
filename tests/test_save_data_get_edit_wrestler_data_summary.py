#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"save_data_get_edit_wrestler_data.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SAVE_DATA_GET_EDIT_WRESTLER_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060051B9","0x003166EC",47,"fb1d5036d90b5023700c012f02b2775cd7c763c0a131ba63904e8f7a6bc56998")
assert m["parameters"]==[{"sequence":1,"name":"wid","type":"WrestlerID"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(19,2,3)
f=s["dll"]["exact_flow"]
assert f["index_call"]["token"]=="0x060051B5"
assert f["collection"]["token"]=="0x040064F5"
assert f["upper_gate"]["count_memberref"]=="0x0A0007A4"
assert f["success"]["item_memberref"]=="0x0A0007A3"
assert s["dll"]["fact_0096_bridge"]["call_il"]=="0x0059"
print("DLL SAVE DATA GET EDIT WRESTLER DATA SUMMARY: PASS")
