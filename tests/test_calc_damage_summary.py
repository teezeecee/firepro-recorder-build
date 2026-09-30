#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"calc_damage.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHMISC_CALC_DAMAGE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004948" and m["rva"]=="0x002AE858"
assert m["signature_blob_hex"]=="00030c080808" and m["return_type"]=="Float32"
assert m["parameters"]==[{"sequence":1,"name":"dp","type":"Int32"},{"sequence":2,"name":"atk_pl_idx","type":"Int32"},{"sequence":3,"name":"def_pl_idx","type":"Int32"}]
assert m["code_size"]==1007 and m["code_sha256"]=="058a61f95c9c59f9e5d3079b2c08a1420599dcec208152325c520e26a5983d04"
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(380,32,15)
assert s["dll"]["integer_adjustments"][3]["raw_mask"]==8 and s["dll"]["integer_adjustments"][4]["raw_mask"]==32
assert [x.get("raw_flag_mask") for x in s["dll"]["table_modifiers"][2:6]]==[512,1024,2048,4096]
assert [x["raw_factor"] for x in s["dll"]["conditional_float_modifiers"][:5]]==[1.125,1.2000000476837158,1.100000023841858,1.2000000476837158,2.5]
assert s["dll"]["apply_damage_bridge"]["fact_id"]=="FACT-0020"
assert s["dll"]["apply_damage_bridge"]["call_ils"]==["0x01E8","0x029A","0x02B9","0x02FD","0x0341","0x0385","0x03C9"]
assert s["dll"]["return_tail"]["il"]=="0x03EC..0x03EE"
print("DLL CALC DAMAGE SUMMARY: PASS")
