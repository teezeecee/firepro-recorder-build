#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"steammanager_get_initialized.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_STEAMMANAGER_GET_INITIALIZED_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060052F1","0x00325EA7",11,"c1bdb25bf14d1778175cda4ec73d358c1891fcc0a65d3b566308883ea29c40ff")
assert (m["method_attributes_raw"],m["tiny_header_byte_raw"],m["body_hex"])==("0x0896","0x2E","28f05200067bf58700042a")
f=s["dll"]["field"]
assert (f["token"],f["name"],f["field_row_hex"],f["signature_blob_hex"])==("0x040087F5","m_bInitialized","01009ad1050008000000","0602")
assert s["dll"]["internal_methoddef_calls"]==[{"token":"0x060052F0","method":"SteamManager.get_Instance","fact_id":"FACT-0213","call_il":"0x0000"}]
r=s["dll"]["direct_in_assembly_references"]
assert len(r)==12 and len({x["caller_token"] for x in r})==12 and {x["opcode"] for x in r}=={"call"}
assert any(x["caller_token"]=="0x06004B65" and x["call_il"]=="0x0000" for x in r)
c=s["capture_boundary"]
assert c["steammanager_get_initialized_row_count"]==0 and c["steammanager_get_instance_row_count"]==0 and c["network_online_check_row_count"]==0 and c["promoted_as_evidence"] is False
assert s["selection_boundary"]["next_after_helper"]["token"]=="0x06004B65"
print("DLL STEAMMANAGER GET INITIALIZED SUMMARY: PASS")
