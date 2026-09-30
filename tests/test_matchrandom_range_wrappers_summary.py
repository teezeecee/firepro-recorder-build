#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"matchrandom_range_wrappers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCHRANDOM_RANGE_WRAPPERS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["signature_blob_hex"],a["code_size"],a["code_sha256"])==(
 "0x0600497B","0x002B107D","0002080808",30,"d6ed5dd5c1cdf595ca459ddc1c740ce66543e9630786cfdc9bf3404247f643f6")
assert a["parameters"]==[{"sequence":1,"name":"min","type":"Int32"},{"sequence":2,"name":"max","type":"Int32"}]
assert a["memberref"]["parent_type_ref"]=="UnityEngine.Random" and a["memberref"]["token"]=="0x0A0001EC"
assert a["last_result_field"]=={"name":"lastRandNum_Int","token":"0x0400578F","type":"Int32"}
assert (b["token"],b["rva"],b["signature_blob_hex"],b["code_size"],b["code_sha256"])==(
 "0x0600497C","0x002B109C","00020c0c0c",30,"088e4cd8eb7a187b28b71251188f91e260b6c7189cf32a45b89f6cd38b1868dc")
assert b["parameters"]==[{"sequence":1,"name":"min","type":"Float32"},{"sequence":2,"name":"max","type":"Float32"}]
assert b["memberref"]["parent_type_ref"]=="UnityEngine.Random" and b["memberref"]["token"]=="0x0A000804"
assert b["last_result_field"]=={"name":"lastRandNum_Float","token":"0x04005790","type":"Float32"}
assert s["dll"]["shared"]["random_count_field"]=={"name":"randomCnt","token":"0x0400578E","type":"Int32"}
assert s["dll"]["caller_bridges"][0]["arguments"]==[0,100]
assert s["dll"]["caller_bridges"][1]["arguments"]==[0.0,1.0]
print("DLL MATCHRANDOM RANGE WRAPPERS SUMMARY: PASS")
