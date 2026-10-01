#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_object_lookups.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_OBJECT_LOOKUPS_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x060050B2","0x0030A47D",6,"9520016c102a2a51bd00c0108de13b24734f1b686f000e2460083dd39da009ee")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(2,0,0)
assert a["exact_body"]==["ldsfld 0x040062DC RefereeMan.inst","ret"]
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x060050B6","0x0030A4C3",9,"aa2a417db5ba1940541d91f5a98fe26ec59230af147fdb4dd2e768ca0dad1e4d")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(5,0,0)
assert b["exact_body"]==["ldarg.0","ldfld 0x040062DE RefereeObj","ldc.i4.0","ldelem.ref","ret"]
assert s["dll"]["fact_0064_bridge"]["calls"][0]["il"]=="0x0009"
assert s["dll"]["fact_0064_bridge"]["calls"][1]["il"]=="0x000E"
print("DLL REFEREE OBJECT LOOKUPS SUMMARY: PASS")
