#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"segment_intersection.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_SEGMENT_INTERSECTION_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["code_size"],a["code_sha256"])==("0x06004A8E",32,"d5ac4557f63717bfd9e57b204629c1e68dee69af19ff1f8c5842fb5667808c6f")
assert (b["token"],b["code_size"],b["code_sha256"])==("0x06004A92",416,"3ecf11f34c121c71dd42aa6aa5ea214ce1417008a01246410a71ef504a537f76")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(151,2,4)
assert s["dll"]["cross_product_expression"]=="a.x * b.y - a.y * b.x"
assert s["dll"]["intersection"]["first_gate"]["opcode"]=="blt.un"
assert s["dll"]["intersection"]["second_gate"]["opcode"]=="blt.un"
assert s["dll"]["fact_0053_bridge"]["call_il"]=="0x0214"
print("DLL SEGMENT INTERSECTION SUMMARY: PASS")
