#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_change_bgm_progress.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_CHANGE_BGM_PROGRESS_V1"
m=s["dll"]["change_bgm_progress"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06005292","0x003220C0",269,"29648ba9313068964c8561e9f85d81f876629060fb99ee22e3b18e160e3b77b5")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(84,9,18)
assert [x["value"] for x in m["strings"]]==["Sound/Bgm/","Sound/OrganizationManagement/BGM/"]
assert m["canonical_calls"]["update_state"]["fact_id"]=="FACT-0163"
assert m["canonical_calls"]["cochange_factory"]["fact_id"]=="FACT-0115"
assert m["canonical_calls"]["audio_clip_set"]["fact_id"]=="FACT-0113"
assert m["canonical_calls"]["play_bgm"]["fact_id"]=="FACT-0132"
g=s["dll"]["get_bgm_info_menu"]
assert (g["token"],g["rva"],g["code_size"],g["code_sha256"])==("0x0600526E","0x0032025D",8,"9cd18fdda1bfb9a6545243b98a151f8e8bc2fd604a36f2611c82a99548ff4eb2")
assert g["field"]["token"]=="0x0400862D"
assert s["dll"]["fact_0161_bridge"]["call_il"]=="0x000C"
print("DLL MENU SOUND CHANGE BGM PROGRESS SUMMARY: PASS")
