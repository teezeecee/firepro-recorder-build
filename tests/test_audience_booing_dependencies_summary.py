#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audience_booing_dependencies.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIENCE_BOOING_DEPENDENCIES_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x060047D7","0x0028FE43",50,"36b8ed39e946a670d66af8344565ee39ada17a831fb66a84935def5e66450dc0")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(20,1,2)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x060047D9","0x0028FEB0",171,"ae89176689967732040134fd4991d756cbe400831f634051ea2aacea57113a6b")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(66,5,4)
assert s["dll"]["tension_down"]["calls"][1]["arguments"]==[0,False]
assert s["dll"]["play_cheer_voice"]["zero_test"]["opcode"]=="bne.un"
assert s["dll"]["play_cheer_voice"]["throttle"]["raw_modulus"]==20
assert s["dll"]["play_cheer_voice"]["dispatch"]["token"]=="0x060052AC"
assert [(x["il"],x["raw_arguments"]) for x in s["dll"]["fact_0078_bridge"]["calls"]]==[("0x0038",[9,0]),("0x0054",[])]
print("DLL AUDIENCE BOOING DEPENDENCIES SUMMARY: PASS")
