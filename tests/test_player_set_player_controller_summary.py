#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_set_player_controller.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_SET_PLAYER_CONTROLLER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004EAC","0x002DE380",138,"5dd13b1056dacf616fe2c9832bf85dbc4901c3911bfc2b75200c1f23b9301acb")
assert (m["methoddef_row_hex"],m["signature_blob_hex"])==("80e32d00000086006c70030072c40200303a","20010111a7b4")
assert (m["header_format"],m["fat_flags_size_raw"],m["max_stack"],m["local_signature_token"])==("fat","0x3013",2,"0x00000000")
assert [m["switch_targets"][f"raw_{i}"]["source_field"] for i in range(6)]==["plCont_NoControl","plCont_Pad","plCont_AI","plCont_Tutorial","plCont_NetCom","plCont_External"]
assert m["switch_targets"]["default"]["effect"]=="return without writing plController"
assert s["dll"]["internal_methoddef_calls"]==[]
r=s["dll"]["direct_reference_surface"]
assert (r["direct_reference_count"],r["direct_caller_method_count"])==(25,11)
assert r["opcode_counts"]=={"call":4,"callvirt":21,"newobj":0,"jmp":0,"ldftn":0,"ldvirtftn":0}
assert r["normalized_reference_map_sha256"]=="59539d1a2da184455e68f1c4a254cb2ba24645dcf251f48b646ee6c1676ec5e5"
assert s["dll"]["pinned_caller_boundaries"][0]["call_ils"]==["0x006F","0x0186"]
c=s["capture_boundary"]
assert c["player_set_player_controller_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["promoted_as_evidence"] is False
assert s["selection_boundary"]["remaining_open_child"]["token"]=="0x0600505D"
print("DLL PLAYER SET PLAYER CONTROLLER SUMMARY: PASS")
