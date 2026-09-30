#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"process_anm_loop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PROCESS_ANM_LOOP_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004E74" and m["rva"]=="0x002DA7B4"
assert m["code_size"]==659 and m["code_sha256"]=="dde8322e75ac1a7d5e5eaa9aa4b92b23791040eda59a832fa26da62d75855602"
assert len(s["dll"]["first_loop_only"]["branches"])==3
assert len(s["dll"]["exact_call_sites"])==8
assert s["dll"]["update_animation_bridge"]["fact_id"]=="FACT-0014"
assert s["dll"]["loop_rewind_branch"]["effects"][0]=="currentFormIdx = anm.loopReturnPoint - anm.loopReturnTo - 2"
assert s["dll"]["counted_loop_tail"]["effects"][-1]=="if LoopAnmCnt becomes 0 and target converts true: target.animator.isReqAnmLoopEnd = 1"
print("DLL PROCESS ANM LOOP SUMMARY: PASS")
