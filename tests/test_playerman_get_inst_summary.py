#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playerman_get_inst.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERMAN_GET_INST_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x0600505D","0x00304880",6,"592555acaf96cbd806fb44a0dfd643c83f27267edcf79fe7ab57ec6c0457b1ff")
assert m["methoddef_row_hex"]=="80483000000096003b7f0800b8d40200f73a"
assert m["signature_blob_hex"]=="000012a818" and m["body_hex"]=="7efa6100042a"
f=s["dll"]["field"]
assert (f["token"],f["name"],f["field_row_hex"],f["signature_blob_hex"])==("0x040061FA","inst","160006220100cf380000","0612a818")
r=s["dll"]["direct_reference_surface"]
assert (r["direct_reference_count"],r["direct_caller_method_count"])==(171,102)
assert r["opcode_counts"]=={"call":171,"callvirt":0,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert r["normalized_reference_map_sha256"]=="fd83acc3062a77a8dee1dde7084c989511249701cff57fb1100cb89a6446400c"
assert r["normalized_caller_token_set_sha256"]=="bc51127accf19d7f10201296d4ab08f4904ba0cc486761926070068406e95ff9"
b=s["dll"]["pinned_caller_boundaries"]
assert b[0]["fact_id"]=="FACT-0201" and b[0]["call_ils"]==["0x0000"]
assert b[1]["caller_token"]=="0x06004B48" and b[1]["call_ils"]==["0x0051","0x0164"]
c=s["capture_boundary"]
assert c["player_man_get_inst_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["weapon_update_equipped_row_count"]==0 and c["promoted_as_evidence"] is False
assert s["selection_boundary"]["next_frontier"]["token"]=="0x06004B48"
assert [x["fact_id"] for x in s["selection_boundary"]["canonical_sibling_children"]]==["FACT-0215","FACT-0216","FACT-0217","FACT-0218"]
print("DLL PLAYERMAN GET INST SUMMARY: PASS")
