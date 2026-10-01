#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_play_co_ctor.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_PLAY_CO_CTOR_V1"
assert s["dll"]["owner_type"]=={"name":"<MyMusic_Play_Co>c__IteratorE","token":"0x02000F73"}
assert s["dll"]["methoddef_row"]=={"token":"0x0600750E","row_hex":"a454320000008618eb4f06005c480000d24f","rva":"0x003254A4"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(7,"5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(3,0,1)
assert s["dll"]["call"]["token"]=="0x0A0000EF"
assert s["dll"]["fact_0144_bridge"]["newobj_il"]=="0x0000"
print("DLL MENU SOUND MY MUSIC PLAY CO CTOR SUMMARY: PASS")
