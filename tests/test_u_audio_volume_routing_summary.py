#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_volume_routing.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_VOLUME_ROUTING_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052CF","0x003256B1",31,"2dd474a11591e000678f479f2d90becf09ceca30baa460e3ec548152f79511de"),
 ("0x060052DD","0x00325835",30,"bdcad7e05493de6d828b070a1ebebada023b8623afedb806639dede39f46a105"),
 ("0x060052DE","0x00325854",31,"c77479fb0ce8779178f36cdfedf65a4a1a72293210533a34202937657ad3304b")]
assert s["dll"]["backend_calls"]["set_volume"]["token"]=="0x0A000FB0"
assert s["dll"]["backend_calls"]["get_volume"]["token"]=="0x0A000FBE"
assert m[1]["fallback_call"]=={"token":"0x060052CE","fact_id":"FACT-0150","call_il":"0x0018"}
assert m[2]["sibling_call"]=={"token":"0x060052CF","call_il":"0x0019"}
scan=s["dll"]["direct_methoddef_reference_scan"]
assert scan["set_Volume_Offset"]["call_count"]==1
assert scan["get_Volume_BackEnd"]["all_counts_zero"] is True
assert scan["set_Volume_BackEnd"]["all_counts_zero"] is True
print("DLL U AUDIO VOLUME ROUTING SUMMARY: PASS")
