#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_down_suicide_aftermath.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_DOWN_SUICIDE_AFTERMATH_V1"
ms={m["name"]:m for m in s["dll"]["methods"]}
assert (ms["CalcDownTime"]["token"],ms["CalcDownTime"]["rva"],ms["CalcDownTime"]["code_size"],ms["CalcDownTime"]["code_sha256"])==("0x06004F0D","0x002E6CD0",422,"f02235b113abcab029951822052639084b3692e7924ae6c3b9ac85e4c86a3a88")
assert (ms["ApplySuicideDamage"]["token"],ms["ApplySuicideDamage"]["rva"],ms["ApplySuicideDamage"]["code_size"],ms["ApplySuicideDamage"]["code_sha256"])==("0x06004F0E","0x002E6E84",247,"ab7e73a9dbfa03ab3a998354ee2482425c0cce67a94c2376bb75edb06a5c7446")
assert (ms["CalcDownTime"]["instruction_count"],ms["CalcDownTime"]["branch_instruction_count"],ms["CalcDownTime"]["call_instruction_count"])==(133,21,10)
assert (ms["ApplySuicideDamage"]["instruction_count"],ms["ApplySuicideDamage"]["branch_instruction_count"],ms["ApplySuicideDamage"]["call_instruction_count"])==(99,0,8)
assert s["dll"]["calc_down_time"]["raw_branch_opcodes"]=={"ring_hp_sp_continue":"bgt.un","ten_count_hp_skip":"blt.un"}
assert s["dll"]["apply_suicide_damage"]["skill_field_tokens"]=={"HP":"0x04007C65","SP":"0x04007C66","Neck":"0x04007C67","Arm":"0x04007C68","Waist":"0x04007C69","Leg":"0x04007C6A"}
assert s["dll"]["update_animation_bridge"]["calls"]==[["CalcDownTime","0x0270","target"],["ApplySuicideDamage","0x029A","host"],["CalcDownTime","0x02A5","host"]]
print("DLL PLAYER DOWN/SUICIDE AFTERMATH SUMMARY: PASS")
