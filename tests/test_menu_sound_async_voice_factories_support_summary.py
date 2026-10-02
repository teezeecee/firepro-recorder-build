#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_async_voice_factories_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_ASYNC_VOICE_FACTORIES_SUPPORT_V1"
f=s["dll"]["factories"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in f]==[
 ("0x06005288","0x00321C54",22,"0b3dccaf04ab02d9fd75b42e066f836adf54e8527cbcd19cdf6f30b73fcaddf7"),
 ("0x0600528C","0x00321D6C",22,"0413ed4cc600423712fb04ffb304151d30a4e14f33179c35e29c80390992c958")]
assert f[0]["generated_type_token"]=="0x02000F68" and f[0]["constructor_token"]=="0x060074CB"
assert f[0]["stored_parameter_fields"]=={"request":"0x0400C207","background":"0x0400C211"}
assert f[0]["open_execution_method"]["code_size"]==1521
assert f[1]["generated_type_token"]=="0x02000F6A" and f[1]["constructor_token"]=="0x060074D7"
assert f[1]["stored_parameter_fields"]=={"type":"0x0400C221","background":"0x0400C225"}
assert f[1]["open_execution_method"]["code_size"]==411
assert len(f[0]["support"])==5 and len(f[1]["support"])==5
print("DLL MENU SOUND ASYNC VOICE FACTORIES SUPPORT SUMMARY: PASS")
