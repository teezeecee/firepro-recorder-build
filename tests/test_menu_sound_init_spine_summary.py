#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_init_spine.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_INIT_SPINE_V1"
m={x["token"]:x for x in s["dll"]["methods"]}
assert (m["0x0600527B"]["code_size"],m["0x0600527B"]["code_sha256"])==(7,"6e817ef204d70afc9203c9b23a4ac0c48eef5f9317a62a9d916cb6e6875bffd6")
assert (m["0x0600527D"]["code_size"],m["0x0600527D"]["code_sha256"])==(7,"0151580d8e132f0a6a0dcb6f2286d921d85461fb76c79ddda417ea011c1c9d28")
assert (m["0x0600527E"]["code_size"],m["0x0600527E"]["code_sha256"])==(66,"f132c681f5788ca9c7581ed581d24de4c4acd0f6c7edb55614cc6ab165b6cf32")
assert m["0x0600527F"]["body_hex"]=="2a"
assert (m["0x06005280"]["code_size"],m["0x06005280"]["code_sha256"])==(236,"11a01435a5eb88584d4a811a33bda97f11287b086c17dbae432748e51e0e4d23")
assert m["0x06005280"]["direct_calls"]["get_instance"]["fact_id"]=="FACT-0112"
assert m["0x06005280"]["direct_calls"]["resume_state"]["status"]=="OPEN_DIRECT_INTERNAL"
assert m["0x06005280"]["strings"][-1]["relationship_status"]=="NAME_ONLY_EXTERNAL_DISPATCH_NOT_DIRECT_METHODDEF_EDGE"
assert s["dll"]["array_counts"]=={"audioClipInfo":39,"audioSrcInfo":8,"audio_sources_attached":8,"lockTimes":39}
assert s["dll"]["remaining_direct_internal_dependencies"]==[{"token":"0x06005281","name":"Menu_SoundManager.Resume_State","body_size":42},{"token":"0x06005283","name":"Menu_SoundManager.Load_SystemSe","body_size":84}]
print("DLL MENU SOUND INIT SPINE SUMMARY: PASS")
