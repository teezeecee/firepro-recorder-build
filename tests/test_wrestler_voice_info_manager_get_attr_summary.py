#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_manager_get_attr.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_MANAGER_GET_ATTR_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060011E8","0x0006F1C8","20021287bc11aa3c08")
assert (m["code_size"],m["code_sha256"])==(58,"3e6d24308c5d970566cd1d5d912792e1ff4ba9bbc71aad81a62da600b2b772c4")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(2,"0x1100034D","07011287c0")
assert m["parameters"]==[{"sequence":1,"name":"type","type":"WrestlerVoiceTypeEnum","type_token":"0x02000A8F"},{"sequence":2,"name":"idx","type":"Int32"}]
assert s["dll"]["calls"]["get_info"]["fact_id"]=="FACT-0181"
assert s["dll"]["calls"]["get_count"]["token"]=="0x0A00078A"
assert s["dll"]["calls"]["get_item"]["token"]=="0x0A00078B"
r=s["dll"]["inbound_direct_reference"]
assert (r["caller_token"],r["call_il"],r["callee_token"])==("0x06004EB4","0x00EC","0x060011E8")
print("DLL WRESTLER VOICE INFO MANAGER GET ATTR SUMMARY: PASS")
