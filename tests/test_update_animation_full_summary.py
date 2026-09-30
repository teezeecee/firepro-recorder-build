#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"update_animation_full.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_UPDATE_ANIMATION_FULL_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E7E" and m["rva"]=="0x002DB890"
assert m["signature_blob_hex"]=="200001" and m["parameters"]==[]
assert m["code_size"]==738 and m["code_sha256"]=="1e18c732ea0674fae8fdecc0b0d06fc976ec4494df663156925e99c4485b4c00"
assert len(s["dll"]["exact_call_sites"])==14
assert s["dll"]["form_flags"]==[
 {"mask":4,"effect":"AnmHostPlayer = plObj.PlIdx"},
 {"mask":32,"effect":"MatchMisc.ApplyDamage(plObj.PlIdx, plObj.TargetPlIdx); if target Player converts true: target.CalcDownTime()"},
 {"mask":16,"effect":"plObj.plCont_AI.EndPriAct(); plObj.ApplySuicideDamage(); plObj.CalcDownTime()"}
]
assert s["dll"]["timer_tail"]==[
 "if AnmStopTimer != 0: AnmStopTimer -= 1",
 "else: FormDispDuration -= 1",
 "return"
]
assert s["dll"]["previous_fact_bridge"]["fact_id"]=="FACT-0005"
print("DLL UPDATE ANIMATION FULL SUMMARY: PASS")
