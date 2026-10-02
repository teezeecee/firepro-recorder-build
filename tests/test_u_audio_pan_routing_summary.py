#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_pan_routing.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_PAN_ROUTING_V1"
g,st=s["dll"]["methods"]
assert (g["token"],g["rva"],g["code_size"],g["code_sha256"])==("0x060052D8","0x003257B9",35,"5de8447700a271c9b17ec8f23fe06668678a0e89c5a9b825074dc77fdc1763b4")
assert g["audio_call"]["token"]=="0x0A000FBA"
assert (st["token"],st["rva"],st["code_size"],st["code_sha256"])==("0x060052D9","0x003257DD",30,"32af8b52722443f3611991f370d4beb536ebfe0f4813884b525bcf4dbc8a0041")
assert st["audio_call"]["token"]=="0x0A000FBB"
assert s["dll"]["object_inequality"]["token"]=="0x0A00000F"
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO PAN ROUTING SUMMARY: PASS")
