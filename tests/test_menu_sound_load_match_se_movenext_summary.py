#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_match_se_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_MATCH_SE_MOVENEXT_V1"
m=s["dll"]["move_next"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060074BA","0x003238A0",361,"f80edfba4bbae0a9f8538fe6abf28795445ad07b7558bd988c5f9fec8b79eed0")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(104,12,7)
assert m["state_switch"]=={"raw_state_0_target":"0x0021","raw_state_1_target":"0x012E","default_target":"0x0165"}
assert m["canonical_call"]=={"token":"0x06005273","fact_id":"FACT-0062","call_il":"0x0070"}
assert m["load_async_factory_call"]=={"token":"0x06005285","call_il":"0x010B"}
assert s["dll"]["closure"]["callback"]["code_sha256"]=="c464156a84c67e9523c5fc1d5c43ef0acd8dffd406b94f26963b58f17742069d"
f=s["dll"]["load_async_factory"]
assert (f["token"],f["code_size"],f["code_sha256"])==("0x06005285",22,"374fd489b8e5ddd8431fbfedf3f2441f6c2ae47f54ae83bada355263b3af9fe0")
assert s["dll"]["open_execution_method"]["token"]=="0x060074C0"
print("DLL MENU SOUND LOAD MATCH SE MOVENEXT SUMMARY: PASS")
