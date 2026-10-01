#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"save_data_is_dlc_installed.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SAVE_DATA_IS_DLC_INSTALLED_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060051C9","0x00316C6C","2001021185c8")
assert (m["code_size"],m["code_sha256"])==(45,"d353bf6e7046434074ecca1c5a62cb8cd9ec636500659fc5b9083f2943c7d841")
assert m["parameters"]==[{"sequence":1,"name":"dlc","type":"DLCEnum"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(21,3,2)
assert s["dll"]["field"]=={"name":"SaveData.dlcVersion","token":"0x0400650C","signature_blob_hex":"061d08","type":"Int32[]"}
assert s["dll"]["calls"]["owner_gate"]["token"]=="0x06001033"
assert s["dll"]["calls"]["recursive"]["raw_argument"]==2
assert s["dll"]["raw_special_value"]==3
assert s["dll"]["fact_0117_bridge"]["call_il"]=="0x0027"
print("DLL SAVE DATA IS DLC INSTALLED SUMMARY: PASS")
