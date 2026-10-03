#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"playerman_get_plobj_from_pad_port.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERMAN_GET_PLOBJ_FROM_PAD_PORT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005066","0x00304B88",103,"9a4d894da22ead6979e399924710d5823a3a505447e40ef6b8c838c6e4b5123e")
assert (m["methoddef_row_hex"],m["signature_blob_hex"])==("884b3000000086003a430a00d5d40200fe3a","200112a78808")
assert (m["header_format"],m["fat_flags_size_raw"],m["max_stack"],m["local_signature_token"])==("fat","0x3013",2,"0x1100003A")
assert s["dll"]["external_member_refs"]==[{"token":"0x0A00000F","name":"op_Inequality","memberref_row_hex":"d100000088500600b6480000","signature_blob_hex":"00020212691269","call_il":"0x0010","opcode":"call"}]
fields=s["dll"]["fields"]
assert [(x["token"],x["name"]) for x in fields]==[("0x040061FF","PlObj"),("0x0400602B","plController"),("0x04006115","kind"),("0x04006031","plCont_NetCom"),("0x040061C6","port")]
assert fields[2]["raw_required_value"]==4
assert s["dll"]["internal_methoddef_calls"]==[]
r=s["dll"]["direct_in_assembly_references"]
assert len(r)==2 and {x["caller_token"] for x in r}=={"0x06004B48"} and {x["opcode"] for x in r}=={"callvirt"}
assert [x["call_il"] for x in r]==["0x0057","0x016B"]
assert s["dll"]["normalized_reference_map_sha256"]=="c50055b67a32cc2fba819ec1c1e2bd555bebd543a466406f7e99677d0481cf91"
c=s["capture_boundary"]
assert c["playerman_get_plobj_from_pad_port_row_count"]==0 and c["network_is_sync_input_data_row_count"]==0 and c["promoted_as_evidence"] is False
assert s["selection_boundary"]["next_bounded_child"]["token"]=="0x06004EAC"
print("DLL PLAYERMAN GET PLOBJ FROM PAD PORT SUMMARY: PASS")
