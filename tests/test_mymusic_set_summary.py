#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"mymusic_set.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MYMUSIC_SET_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06002C23","0x001AE857","00020111aa240e")
assert (m["code_size"],m["code_sha256"])==(44,"d390c42b59fdb5e492f5477ea4ebd30bb039048a3feebf4e7b82d7f2dd35a59a")
assert m["parameters"]==[{"sequence":1,"name":"bgm_mode","type":"SYSTEM_SOUND"},{"sequence":2,"name":"fname","type":"String"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(14,5,0)
assert s["dll"]["fields"]["raw_33_target"]["token"]=="0x04008705"
assert s["dll"]["fields"]["raw_34_target"]["token"]=="0x04008704"
assert [x["call_il"] for x in s["dll"]["fact_0108_bridges"]]==["0x00C4","0x00D7"]
assert all(x["raw_bgm_mode"]==33 for x in s["dll"]["fact_0108_bridges"])
print("DLL MYMUSIC SET SUMMARY: PASS")
