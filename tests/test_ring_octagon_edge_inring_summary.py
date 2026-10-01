#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"ring_octagon_edge_inring.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_RING_OCTAGON_EDGE_INRING_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060050EE","0x0030C4F9",15,"feb37d8722b81f775838d19746a28c526247c92c902c0e4437baddbb786034ef")
assert m["parameters"]==[{"sequence":1,"name":"range","type":"Float32"},{"sequence":2,"name":"p","type":"Vector2"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(7,0,1)
assert s["dll"]["field"]["name"]=="colData_InsideRing"
assert s["dll"]["inner_call"]["token"]=="0x060050ED"
assert s["dll"]["exact_body"][-2:]==["call Ring.TestCollision_OctagonEdge","ret"]
assert s["dll"]["fact_0089_bridge"]["call_il"]=="0x005A"
print("DLL RING OCTAGON EDGE INRING SUMMARY: PASS")
