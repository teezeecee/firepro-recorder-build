#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_my_music_play.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_MY_MUSIC_PLAY_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052B8","0x00323130","20020211aa2411aa18")
assert (m["code_size"],m["code_sha256"])==(481,"e84b8a91478acffadf8ee5f39f17855e421d0cf1b4d482f97dfbb53700440a5a")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(2,"0x11001213","07030e0215118839011182c1")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(120,15,25)
assert s["dll"]["strings"]["mp3"]["value"]==".mp3"
assert s["dll"]["strings"]["coroutine_name"]["value"]=="MyMusic_Play_Co"
assert s["dll"]["calls"]["check_file"]["call_ils"]==["0x0026","0x0065","0x011C"]
assert s["dll"]["calls"]["add_component"]["call_ils"]==["0x00CF","0x0186"]
assert s["dll"]["fact_0132_bridge"]["call_il"]=="0x0066"
print("DLL MENU SOUND MY MUSIC PLAY SUMMARY: PASS")
