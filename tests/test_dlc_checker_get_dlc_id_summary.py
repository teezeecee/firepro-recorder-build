#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"dlc_checker_get_dlc_id.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_DLC_CHECKER_GET_DLC_ID_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06001036","0x0005F840","00011185d01185c8")
assert (m["code_size"],m["code_sha256"])==(143,"e71bcaa68daa57d26a04e13b1d43b7761db94df3724f312e48ce26b7d81e5442")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(31,2,0)
raw=s["dll"]["raw_mapping"]
assert [x["dlc_enum_raw"] for x in raw]==list(range(13))
assert [x["dlc_id_raw"] for x in raw]==[758160,775630,912460,1037890,766550,1104260,1121430,1120550,1120540,1191160,1191161,1191162,3932720]
assert s["dll"]["default"]["return_raw"]==-1
assert s["dll"]["fact_0120_bridge"]["call_il"]=="0x0001"
print("DLL DLC CHECKER GET DLC ID SUMMARY: PASS")
