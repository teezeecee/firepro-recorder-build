#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_async_referee_voice_factory_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_ASYNC_REFEREE_VOICE_FACTORY_SUPPORT_V1"
f=s["dll"]["factory"]
assert (f["token"],f["rva"],f["code_size"],f["code_sha256"])==("0x0600528A","0x00321CE4",15,"506732d3b9f0d6b4d7a4cf027d9a8c32bb1764f113000e24f2f72153caf4eb27")
assert f["parameters"]==[{"sequence":1,"name":"type","type":"RefereeVoiceTypeEnum","type_token":"0x02000A8D"}]
assert f["generated_type_token"]=="0x02000F69" and f["constructor_token"]=="0x060074D1"
sup=s["dll"]["support"]
assert [x["token"] for x in sup]==["0x060074D1","0x060074D3","0x060074D4","0x060074D5","0x060074D6"]
assert sup[3]["body_hex"]=="02177d1fc2000402157d20c200042a"
assert sup[4]["body_hex"]=="73ee00000a7a"
o=s["dll"]["open_execution_method"]
assert (o["token"],o["rva"],o["code_size"],o["code_sha256"])==("0x060074D2","0x00324470",311,"b7cd1752de05dfc07cc79a9b416fd025358fd0f6d9041e7c03f72b564c054b64")
print("DLL MENU SOUND LOAD ASYNC REFEREE VOICE FACTORY SUPPORT SUMMARY: PASS")
