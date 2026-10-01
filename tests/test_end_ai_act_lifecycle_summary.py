#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"end_ai_act_lifecycle.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYERCONTROLLER_AI_END_AI_ACT_LIFECYCLE_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==(
 "0x06004FAD","0x002F60F5",33,"596a7249879f79a09b58884b3296525e4a2fd50a7549e53565f10b10b6d91d2f")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(13,1,1)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==(
 "0x0600500B","0x002FD4D7",38,"4f3be7710b4a49b035c4f3d0bcc0be43bc6a36afb09368200886656b9e6ae460")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(13,1,1)
assert s["dll"]["fields"]["keepLastSkill"]["token"]=="0x0400616A"
assert s["dll"]["fields"]["currentPriAct"]["token"]=="0x04006151"
assert s["dll"]["caller_bridges"][0]["fact_id"]=="FACT-0014"
assert s["dll"]["caller_bridges"][1]["call_il"]=="0x025D"
print("DLL END AI ACT LIFECYCLE SUMMARY: PASS")
