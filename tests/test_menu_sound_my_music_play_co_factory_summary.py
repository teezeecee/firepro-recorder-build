#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_play_co_factory.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_PLAY_CO_FACTORY_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052B9","row_hex":"203332000000810018620a006a550000483d","rva":"0x00323320"}
m=s["dll"]["method"]
assert (m["signature_blob_hex"],m["return_type_token"])==("2000128181","0x01000060")
assert (m["code_size"],m["code_sha256"])==(8,"8b924ec5650c79c888696f801976f2f99b92a71ba35fb44d7fcabce6d6e4c799")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==("0x0013",1,"0x11001214","070112bdcc")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,1)
assert s["dll"]["local"]["type_token"]=="0x02000F73"
assert s["dll"]["constructor"]["token"]=="0x0600750E"
rel=s["dll"]["fact_0133_related_string_observation"]
assert (rel["string_token"],rel["call_il"],rel["relationship_status"])==("0x7008EBBE","0x01D9","NAME_ONLY_EXTERNAL_DISPATCH_NOT_DIRECT_CALL")
print("DLL MENU SOUND MY MUSIC PLAY CO FACTORY SUMMARY: PASS")
