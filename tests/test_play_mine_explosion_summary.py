#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"play_mine_explosion.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MATCH_EFFECT_PLAY_MINE_EXPLOSION_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==(
 "0x060048CB","0x002A4AA4",152,"fc8982922fb7bba57f9f0052110e69463503c4f343c90fc030846e61e7a2e049")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(51,3,19)
assert s["dll"]["prefab_block"]["field"]=={"name":"Prefab_RopeExplosion","token":"0x04005679"}
assert s["dll"]["prefab_block"]["false_target"]=="0x007C"
assert s["dll"]["shared_tail"]==["Ring.GetInst().mRingShake(10)","MatchCamera.GetInst().ReqVivration(2.0f)","return"]
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0049" and s["dll"]["caller_bridge"]["call_il"]=="0x030F"
print("DLL PLAY MINE EXPLOSION SUMMARY: PASS")
