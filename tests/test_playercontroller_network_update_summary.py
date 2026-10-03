#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playercontroller_network_update.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_NETWORK_UPDATE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005038","0x00300658",94,"6263d3075a2b1147709139a168d07a8b4f9b6773a41b67ff169759a6fe4482ed")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["local_signature_token"],m["local_signature_blob_hex"])==("580630000000c600edc800005c480000eb3a","200001","0x11001143","070111a5ac")
assert (m["fat_flags_size_raw"],m["max_stack"])==("0x3013",3)
assert [x["fact_id"] for x in s["dll"]["canonical_methoddef_calls"]]==["FACT-0220","FACT-0212","FACT-0211"]
assert [x["token"] for x in s["dll"]["fields"]]==["0x040061C6","0x04005AF2","0x04006117","0x04005AF3","0x04006118","0x04005AF1","0x040061C7","0x04006116","0x04006119"]
assert len(s["dll"]["exact_control_blocks"])==4
r=s["dll"]["direct_reference_surface"]
assert (r["direct_reference_count"],r["direct_caller_method_count"])==(0,0)
assert r["normalized_reference_map_sha256"]=="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e06ecb64b4a728a08c04f7d"
c=s["capture_boundary"]
assert c["playercontroller_network_update_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["network_get_input_data_row_count"]==0 and c["network_get_grapple_result_row_count"]==0 and c["promoted_as_evidence"] is False
print("DLL PLAYERCONTROLLER NETWORK UPDATE SUMMARY: PASS")
