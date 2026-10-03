#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"dispnotification_show.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_DISPNOTIFICATION_SHOW_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060049C3","0x002B2C33",39,"ce3eb15bbbe9c74bd34eb1405194a3556fbdfabec4a4c4cb4c53f72389a61a14")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"],m["signature_blob_hex"])==("0x0086","0x9E","2002010e08")
assert m["body_hex"]=="02282800000a176f0301000a027b46580004036f6303000a02047d4758000402177d455800042a"
assert s["dll"]["internal_methoddef_calls"]==[]
assert [(x["token"],x["name"]) for x in s["dll"]["external_member_refs"]]==[("0x0A000028","get_gameObject"),("0x0A000103","SetActive"),("0x0A000363","set_text")]
assert [(x["token"],x["name"]) for x in s["dll"]["fields"]]==[("0x04005846","text_Message"),("0x04005847","duration"),("0x04005845","State")]
assert s["dll"]["fields"][2]["raw_value"]==1
r=s["dll"]["direct_in_assembly_references"]
assert len(r)==6 and len({x["caller_token"] for x in r})==2 and {x["opcode"] for x in r}=={"callvirt"}
assert [x["call_il"] for x in r if x["caller_token"]=="0x06004B48"]==["0x00A7","0x00C0","0x01C1","0x01ED"]
assert s["dll"]["normalized_reference_map_sha256"]=="1d5050de4c98c6eacfc0231b8ecfcbaeee541df288bc959a74430f8e9168bae3"
c=s["capture_boundary"]
assert c["dispnotification_show_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["matchdebug_test_notification_row_count"]==0 and c["promoted_as_evidence"] is False
assert s["selection_boundary"]["next_bounded_child"]["token"]=="0x06005066"
print("DLL DISPNOTIFICATION SHOW SUMMARY: PASS")
