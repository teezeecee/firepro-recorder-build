#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_async_referee_voice_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_ASYNC_REFEREE_VOICE_MOVENEXT_V1"
assert s["dll"]["owner_type"]=={"name":"<LoadAsync_RefereeVoice>c__Iterator4","token":"0x02000F69","factory_support_fact_id":"FACT-0172"}
assert s["dll"]["methoddef_row"]=={"token":"0x060074D2","row_hex":"704432000000e6017f5a0600db490000d24f","rva":"0x00324470"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(311,"b7cd1752de05dfc07cc79a9b416fd025358fd0f6d9041e7c03f72b564c054b64")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==("0x0013",4,"0x1100121A","070309080e")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(105,12,6)
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0021"},{"raw_state":1,"target_il":"0x00D1"}]
assert s["dll"]["static_fields"]["clips"]["token"]=="0x040086FF"
assert s["dll"]["strings"]["index_format"]=={"token":"0x700082AA","value":"{0:D3}","load_il":"0x0066"}
assert s["dll"]["calls"]["resources_load_async"]["call_il"]=="0x0084"
assert s["dll"]["calls"]["wait_for_seconds_ctor"]["newobj_il"]=="0x00B3"
assert s["dll"]["calls"]["request_get_asset"]["call_il"]=="0x0100"
assert s["dll"]["exception_section"] is None
assert s["dll"]["metadata_relationship"]["relationship_status"]=="SAME_GENERATED_TYPE_METHOD_NOT_RUNTIME_CALL"
print("DLL MENU SOUND LOAD ASYNC REFEREE VOICE MOVENEXT SUMMARY: PASS")
