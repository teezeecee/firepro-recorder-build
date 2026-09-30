#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"process_fox_sleep.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_PROCESS_FOX_SLEEP_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004EBE" and m["rva"]=="0x002DEC78"
assert m["signature_blob_hex"]=="200001" and m["parameters"]==[]
assert m["code_size"]==177
assert m["code_sha256"]=="1b6876147c6a2934da2daa0c1ceeaeec1952b91df7391c37ea2521d85157b16f"
assert len(s["dll"]["exact_gate_sequence"])==7
assert s["dll"]["exact_gate_sequence"][4]["raw_values"]==[89,90]
assert s["dll"]["exact_gate_sequence"][5]["raw_value"]==5
assert s["dll"]["exact_gate_sequence"][6]["raw_mask"]==48
assert s["dll"]["effects_when_all_gates_pass"][-1]["callee_token"]=="0x06004ED1"
assert s["dll"]["update_animation_bridge"]["fact_id"]=="FACT-0014"
print("DLL PROCESS FOX SLEEP SUMMARY: PASS")
