#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"network_is_sync_input_data.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_NETWORK_IS_SYNC_INPUT_DATA_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004B48","0x002C1C50",603,"ac9ee661178e8c57fa83c0572a6bc65d650c99c1aff55185cc942f5e5c52c89d")
assert (m["methoddef_row_hex"],m["signature_blob_hex"],m["local_signature_token"],m["local_signature_blob_hex"])==("501c2c0000008600070e0a00db490000ba37","200002","0x11000FBA","0708080812a78802080812a78808")
assert (m["fat_flags_size_raw"],m["max_stack"])==("0x3013",4)
assert [x["fact_id"] for x in s["dll"]["canonical_methoddef_calls"]]==["FACT-0215","FACT-0219","FACT-0217","FACT-0218","FACT-0216"]
assert sum(len(x["sites"]) for x in s["dll"]["canonical_methoddef_calls"])==11
assert len(s["dll"]["external_member_refs"])==5
assert len(s["dll"]["fields"])==12
assert len(s["dll"]["user_strings"])==6
assert len(s["dll"]["exact_control_blocks"])==6
r=s["dll"]["direct_reference_surface"]
assert (r["direct_reference_count"],r["direct_caller_method_count"])==(3,3)
assert r["opcode_counts"]=={"call":2,"callvirt":1,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert r["normalized_reference_map_sha256"]=="cfe844844eb440116d5e4c6af0a210c7cde294b4162cb9b60fc836c894837fba"
assert [x["caller_token"] for x in s["dll"]["direct_callers"]]==["0x06004B59","0x06004B5B","0x06005038"]
c=s["capture_boundary"]
assert c["network_is_sync_input_data_row_count"]==0 and c["network_is_ready_key_data_row_count"]==0 and c["network_clear_key_buffer_row_count"]==0 and c["playercontroller_network_update_row_count"]==0 and c["promoted_as_evidence"] is False
n=s["selection_boundary"]["next_parent_seam"]
assert n["token"]=="0x06005038" and [x["fact_id"] for x in n["canonical_child_calls"]]==["FACT-0220","FACT-0212","FACT-0211"]
print("DLL NETWORK IS SYNC INPUT DATA SUMMARY: PASS")
