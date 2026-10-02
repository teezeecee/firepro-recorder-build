#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_async_wrestler_voice_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_ASYNC_WRESTLER_VOICE_MOVENEXT_V1"
assert s["dll"]["owner_type"]=={"name":"<LoadAsync_WrestlerVoiceList>c__Iterator3","token":"0x02000F68","factory_support_fact_id":"FACT-0176"}
assert s["dll"]["methoddef_row"]=={"token":"0x060074CC","row_hex":"443e32000000e6017f5a0600db490000d24f","rva":"0x00323E44"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(1521,"4a24846ef6fe5b1e729ee484cbdac32e5744eb183a9b23562fd7d865a8410f94")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(5,"0x11001219","070409080e08")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(481,50,40)
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0029"},{"raw_state":1,"target_il":"0x032B"},{"raw_state":2,"target_il":"0x040C"},{"raw_state":3,"target_il":"0x04D2"}]
assert s["dll"]["validation"]["pl_idx"]=={"min":0,"exclusive_max":8}
assert s["dll"]["validation"]["slot"]=={"min":0,"exclusive_max":5}
assert s["dll"]["validation"]["type"]=={"min":0,"exclusive_max":93}
assert s["dll"]["calls"]["bundle_load_async"]["call_il"]=="0x02FF"
assert s["dll"]["calls"]["resources_load"]["call_il"]=="0x03D7"
assert s["dll"]["calls"]["request_is_done"]["call_il"]=="0x04DF"
assert s["dll"]["calls"]["bundle_load_audio_clip"]["callvirt_il"]=="0x0564"
assert s["dll"]["calls"]["bundle_unload"]["callvirt_il"]=="0x05CC"
assert s["dll"]["exception_section"] is None
print("DLL MENU SOUND LOAD ASYNC WRESTLER VOICE MOVENEXT SUMMARY: PASS")
