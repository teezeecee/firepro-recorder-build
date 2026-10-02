#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_async_announcer_voice_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_ASYNC_ANNOUNCER_VOICE_MOVENEXT_V1"
assert s["dll"]["owner_type"]=={"name":"<LoadAsync_AnnouncerVoice>c__Iterator5","token":"0x02000F6A","factory_support_fact_id":"FACT-0176"}
assert s["dll"]["methoddef_row"]=={"token":"0x060074D8","row_hex":"e44532000000e6017f5a0600db490000d24f","rva":"0x003245E4"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(411,"190881f0b3580bf1117c3f937040340778b36c472ddd6d9db01ae15286fa458a")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(4,"0x11000047","070109")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(132,16,6)
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0025"},{"raw_state":1,"target_il":"0x00CD"},{"raw_state":2,"target_il":"0x0135"}]
assert s["dll"]["state_switch"]["default_target_il"]=="0x0197"
assert s["dll"]["strings"]["index_format"]=={"token":"0x700082AA","value":"{0:D3}","load_il":"0x0070"}
assert s["dll"]["calls"]["resources_load_async"]["call_il"]=="0x00A1"
assert s["dll"]["calls"]["wait_for_seconds_ctor"]["newobj_il"]=="0x0117"
assert s["dll"]["exception_section"] is None
print("DLL MENU SOUND LOAD ASYNC ANNOUNCER VOICE MOVENEXT SUMMARY: PASS")
