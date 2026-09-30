#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"critical_check.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_CRITICAL_CHECK_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004949" and m["rva"]=="0x002AEC54"
assert m["signature_blob_hex"]=="0002020808" and m["return_type"]=="Boolean"
assert m["parameters"]==[{"sequence":1,"name":"atk_pl_idx","type":"Int32"},{"sequence":2,"name":"def_pl_idx","type":"Int32"}]
assert m["code_size"]==678 and m["code_sha256"]=="8df067018ec4101a6f4861d7fe438f0ea51a2b50b1f698a9b908698e72352466"
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(226,34,10)
assert [x["raw_divisor"] for x in s["dll"]["three_table_factors"]]==[100,100,100]
f=s["dll"]["fourth_factor"]; assert f["critical_check_masks"]==[2,8,32] and f["raw_mask_group_sp_mask"]==512 and f["raw_alternate_sp_mask"]==1024
assert s["dll"]["post_product_modifiers"][0]["raw_mask"]==4
assert s["dll"]["post_product_modifiers"][1]["cases"]==[{"raw_value":1,"effect":"local8 /= 2.0f"},{"raw_value":3,"effect":"local8 *= 2.0f"}]
assert s["dll"]["random_tail"]["range_token"]=="0x0600497C"
assert s["dll"]["apply_damage_bridge"]["fact_id"]=="FACT-0020"
print("DLL CRITICAL CHECK SUMMARY: PASS")
