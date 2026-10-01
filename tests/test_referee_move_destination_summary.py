#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_move_destination.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_MOVE_DESTINATION_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["code_size"],a["code_sha256"])==("0x0600509E",89,"58c6b30e276aa4ab2b5a5e4116f2f309ebb362cf4a6cb17d52245a744bd6fae1")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(29,2,2)
assert (b["token"],b["code_size"],b["code_sha256"])==("0x0600508B",68,"ead82943535ec77fed4deda04c5e7adf102ba54ee322c82072b58762c619957b")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(23,2,4)
assert s["dll"]["move"]["state_gate"]["raw_value"]==8
assert s["dll"]["reached"]["second_test"]["threshold_float32_bits"]=="0x3D7FFFFF"
assert s["dll"]["fact_0074_bridge"]["call_il"]=="0x0062"
print("DLL REFEREE MOVE DESTINATION SUMMARY: PASS")
