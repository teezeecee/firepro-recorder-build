#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"referee_fight_presentation.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REFEREE_FIGHT_PRESENTATION_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["rva"],a["code_size"],a["code_sha256"])==("0x06005279","0x003216E4",82,"c96840b83bb1f8795fc6e881c61a725201424c4dec3ff5188b932e16e3f1f745")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(24,4,7)
assert (b["token"],b["rva"],b["code_size"],b["code_sha256"])==("0x060049F4","0x002B40A6",13,"4f1688f5e78f6692ef931ec6a1337cb88f04f099e3ec938be0f9d15b2c9fd65e")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(5,0,1)
assert s["dll"]["play_referee_voice"]["throttle"]["raw_modulus"]==20
assert s["dll"]["play_referee_voice"]["dispatch"]["arguments"]==["vid",1.0]
assert s["dll"]["show_fight"]["field"]=={"name":"gameObj_Fight","token":"0x0400589B"}
assert [(x["il"],x["raw_argument"]) for x in s["dll"]["fact_0075_bridge"]["calls"]]==[("0x0053",0),("0x005E",1)]
print("DLL REFEREE FIGHT PRESENTATION SUMMARY: PASS")
