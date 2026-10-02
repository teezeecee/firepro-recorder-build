#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"matchrandom_range.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHRANDOM_RANGE_V1"
assert s["source_ids"]==["DLL-001"]
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x0600497C","0x002B109C","00020c0c0c")
assert (m["header_format"],m["code_size"],m["code_sha256"])==("tiny",30,"088e4cd8eb7a187b28b71251188f91e260b6c7189cf32a45b89f6cd38b1868dc")
assert m["body_hex"]=="7e8e5700041758808e5700040203280408000a80905700047e905700042a"
fields={(x["token"],x["name"],x["signature_blob_hex"]) for x in s["dll"]["static_fields"]}
assert fields=={("0x0400578E","randomCnt","0608"),("0x04005790","lastRandNum_Float","060c")}
ext=s["dll"]["external_member"]
assert (ext["token"],ext["owner"],ext["name"],ext["call_il"])==("0x0A000804","UnityEngine.Random","Range","0x000E")
assert s["dll"]["direct_reference_count"]==7
assert s["dll"]["direct_caller_method_count"]==6
assert len(s["dll"]["direct_in_assembly_references"])==7
assert s["capture_boundary"]["matchrandom_range_row_count"]==0
assert s["capture_boundary"]["promoted_as_evidence"] is False
print("DLL MATCHRANDOM RANGE SUMMARY: PASS")
