#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"autorun_geometry_classifiers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUTORUN_GEOMETRY_CLASSIFIERS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x06004961",18,"654ba7cc9e57f9d89980c22e809e524ea356d0b765da69858346bf5f552f101e"),
 ("0x060050E8",44,"9e30d379778702383767528e435f4f3286a8750330a3c347070a0bd6b2d7f040"),
 ("0x060050E9",26,"176f302c0fcf51b200743023b8c7ca7028e80575b1fb3de87efd6d6bddf130d6")]
assert s["dll"]["area_classifier"]["raw_true_values"]==[2,3]
assert [x["raw_result"] for x in s["dll"]["rhombus_core"]["ordered_mapping"]]==[2,3,4,5]
assert s["dll"]["fact_0050_bridge"]["upper_triangle_call_ils"]==["0x0095","0x00B8","0x00F0","0x0113"]
print("DLL AUTORUN GEOMETRY CLASSIFIERS SUMMARY: PASS")
