#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"steammanager_get_instance.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_STEAMMANAGER_GET_INSTANCE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052F0","0x00325E80",38,"076c5c279b25adcb3393894e49a79529bb680282eeac30b4d08826cacfe852a7")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"])==("0x0891","0x9A")
assert m["body_hex"]=="7ef387000414280600000a391000000072f2f3087073d600000a28e303002b2a7ef38700042a"
assert s["dll"]["field"]["token"]=="0x040087F3" and s["dll"]["field"]["name"]=="s_instance"
assert s["dll"]["internal_methoddef_calls"]==[]
assert s["dll"]["direct_reference_count"]==1 and s["dll"]["direct_caller_method_count"]==1
assert s["dll"]["direct_in_assembly_references"][0]["call_il"]=="0x0000"
assert [x["token"] for x in s["dll"]["external_tokens"]]==["0x0A000006","0x7008F3F2","0x0A0000D6","0x2B0003E3"]
c=s["capture_boundary"];assert c["steammanager_get_instance_row_count"]==0 and c["steammanager_get_initialized_row_count"]==0 and c["promoted_as_evidence"] is False
print("DLL STEAMMANAGER GET INSTANCE SUMMARY: PASS")
