#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_not_implemented_stubs.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_NOT_IMPLEMENTED_STUBS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052D2","0x00325741",6,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c"),
 ("0x060052D3","0x00325748",6,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c"),
 ("0x060052ED","0x00325E63",6,"72cc88b5b683b160abc8e7954fbaf73bc594488ba0cf95ae7d65958b1e21730c")
]
assert [x["signature_blob_hex"] for x in m]==["20001280fd","2001011280fd","200001"]
assert s["dll"]["shared_body_hex"]=="73c503000a7a"
assert s["dll"]["constructor"]["token"]=="0x0A0003C5"
assert s["dll"]["constructor"]["parent_typeref_token"]=="0x01000105"
assert s["dll"]["constructor"]["parent_resolved"]=="System.NotImplementedException"
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO NOT IMPLEMENTED STUBS SUMMARY: PASS")
