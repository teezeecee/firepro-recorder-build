#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"weaponman_drop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_R6_WEAPONMAN_DROP_V1"
assert s["source_ids"]==["DLL-001","CAP-R6-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06006AC9","0x0043541C","2005010811190c11a85c11a768")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("fat",33,"edcc7cf0273d8a9e58e2e252323436fb039630779892b4c0e2e9654eddab7f76")
assert m["body_hex"]=="020328c86a00060a06282a00000a3a010000002a0604050e040e056fb86a00062a"
assert s["dll"]["calls"]["get_weapon_obj"]["canonical_fact"]=="FACT-0192"
inb=s["dll"]["inbound_direct_reference"]
assert (inb["caller_token"],inb["call_il"],inb["callsite_count_inside_caller"])==("0x06004EDF","0x0051",1)
r=s["r6"]
assert (r["player_drop_weapon_execution_count"],r["parent_pre_weaponIdx_negative_count"],r["parent_pre_weaponIdx_nonnegative_count"],r["weapon_drop_execution_count"])==(923,912,11,11)
assert all(v==11 for v in r["relations"].values())
w=s["witness"]
assert (w["record_count"],w["byte_count"],w["sha256"])==(11,1548,"e1d7d7d17a5a18da4ce9110cd4878d2bcdafc6441ca866580f0f4cd24c9c21cf")
print("DLL/R6 WEAPONMAN DROP SUMMARY: PASS")
