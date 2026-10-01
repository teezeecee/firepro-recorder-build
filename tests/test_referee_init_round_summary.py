#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_init_round.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_INIT_ROUND_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x0600507A","0x00305AA0","20010108",244,"e49118b8c0107b96e5bcca09a2cd24853191f05c685c858415a176cac7ba3bc2")
assert m["parameters"]==[{"sequence":1,"name":"rd","type":"Int32","loaded_by_body":False}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(70,6,3)
assert s["dll"]["pl_pos_xy"]["y_when_battle_royal_kind_raw_0"]==1.0
assert s["dll"]["pl_pos_xy"]["y_when_battle_royal_kind_raw_4"]==1.0
assert s["dll"]["pl_pos_xy"]["y_when_other_nonzero_raw_values"]==0.0
a=s["dll"]["request_branch"]["first_path"]; b=s["dll"]["request_branch"]["alternate_path"]
assert (a["state_raw"],a["request_raw"],a["update_referee_anm"])==(22,1106,False)
assert (b["state_raw"],b["request_raw"],b["update_referee_anm"])==(19,1121,True)
assert s["dll"]["shared_tail"]==["PlPos.z = 1.0f","Counter = 0","plIdx_FirstWiner = -1","standPoseTimer = 0"]
assert s["dll"]["fact_0068_bridge"]["call_ils"]==["0x00AB","0x00C3"]
print("DLL REFEREE INIT ROUND SUMMARY: PASS")
