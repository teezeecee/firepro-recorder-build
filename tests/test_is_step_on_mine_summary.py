#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"is_step_on_mine.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_RING_IS_STEP_ON_MINE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x060050FC","0x0030D1B0",324,"c461d4e1d4b587e58b3086f2eb88ae656d7147dbee555c6470ea7bb7a8243ffa")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(91,14,6)
assert s["dll"]["entry"][2]=="if player.Zone != 1: return false"
assert s["dll"]["rotation"]["angle_degrees"]==45.0 and s["dll"]["rotation"]["axis"]==[0.0,0.0,1.0]
assert s["dll"]["thresholds"]=={"center":3.6458330154418945,"inner":4.5833330154418945,"outer":6.4583330154418945}
assert len(s["dll"]["ordered_true_bands"])==4
assert s["dll"]["fact_0049_bridge"]["call_il"]=="0x023F"
print("DLL IS STEP ON MINE SUMMARY: PASS")
