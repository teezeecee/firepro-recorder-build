#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_update_state.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_UPDATE_STATE_V1"
m=s["dll"]["update_state"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005282","0x00321910",180,"0f78bdbd8f0a3abc281912645f9d95b9b3f182a1eae9bf24c948379d3782b6d5")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(48,1,8)
assert m["null_gate"]["get_inst_token"]=="0x06005174"
assert [(x["source_field_name"],x["target_field_name"],x["constant"]) for x in m["normalizations"]]==[
 ("seVol","Volume_Se",100.0),("voiceVol","Volume_Voice",100.0),("cheerVol","Volume_Cheer",100.0),
 ("bgmVol_Menu","Volume_BgmProgress",100.0),("bgmVol_Entrance","Volume_BgmAdmission",100.0),("bgmVol_Match","Volume_BgmBattle",100.0)]
g=s["dll"]["save_data_get_inst"]
assert (g["token"],g["rva"],g["code_size"],g["code_sha256"])==("0x06005174","0x003149C8",6,"2e12171cc208596025d626b80263f5597a296cc70ab5856f40c8660292702f40")
assert g["field"]["token"]=="0x040064EC"
assert s["dll"]["fact_0161_bridge"]["call_il"]=="0x0000"
print("DLL MENU SOUND UPDATE STATE SUMMARY: PASS")
