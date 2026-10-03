#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"network_online_check.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_NETWORK_ONLINE_CHECK_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004B65","0x002C2C5C",26,"ac5bd6e06bc7d05f1d7ee9c98ceac6a1b2977018dbcf86cfe907dd7648953dad")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"],m["body_hex"])==("0x0096","0x6A","28f15200063a02000000162a28340e000a3a02000000162a172a")
assert s["dll"]["internal_methoddef_calls"]==[{"token":"0x060052F1","method":"SteamManager.get_Initialized","fact_id":"FACT-0214","call_il":"0x0000"}]
e=s["dll"]["external_member_refs"][0]
assert (e["token"],e["name"],e["memberref_row_hex"],e["signature_blob_hex"],e["call_il"])==("0x0A000E34","BLoggedOn","910f000059530700634a0000","000002","0x000C")
r=s["dll"]["direct_reference_surface"]
assert (r["direct_reference_count"],r["direct_caller_method_count"])==(22,16)
assert r["opcode_counts"]=={"call":22,"callvirt":0,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert r["normalized_reference_map_sha256"]=="b3adc0cc33c4c6c00d6d6e95044da098b1acabe34f6055dee111af9a3e49a863"
assert r["normalized_caller_token_set_sha256"]=="7cd18ccf031bc7cd391d14885901accf25d342887966210b78d6150a4f856c38"
assert any(x["caller_token"]=="0x06004B48" and x["call_ils"]==["0x000D"] for x in s["dll"]["pinned_caller_boundaries"])
c=s["capture_boundary"]
assert c["network_online_check_row_count"]==0 and c["steammanager_get_initialized_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["promoted_as_evidence"] is False
print("DLL NETWORK ONLINE CHECK SUMMARY: PASS")
