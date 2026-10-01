#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_play_co_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_PLAY_CO_MOVENEXT_V1"
assert s["dll"]["owner_type"]["token"]=="0x02000F73"
assert s["dll"]["methoddef_row"]=={"token":"0x0600750F","row_hex":"ac5432000000e6017f5a0600db490000d24f","rva":"0x003254AC"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(328,"19dabb20d473fa3b479ae5e4d54dd67e44063fc7b40e2537738b472ce9dbeb98")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(4,"0x11000047","070109")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(98,11,11)
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0025"},{"raw_state":1,"target_il":"0x006F"},{"raw_state":2,"target_il":"0x00B6"}]
assert s["dll"]["strings"]["file_prefix"]=={"token":"0x7008EBDE","value":"file://","load_il":"0x0026"}
assert s["dll"]["calls"]["wait_end_of_frame_ctor"]["call_ils"]==["0x0051","0x0098"]
assert s["dll"]["calls"]["get_audio_clip"]["call_il"]=="0x0088"
assert s["dll"]["calls"]["play"]["call_il"]=="0x011B"
assert s["dll"]["metadata_relationship"]["relationship_status"]=="SAME_GENERATED_TYPE_METHOD_NOT_RUNTIME_CALL"
print("DLL MENU SOUND MY MUSIC PLAY CO MOVENEXT SUMMARY: PASS")
