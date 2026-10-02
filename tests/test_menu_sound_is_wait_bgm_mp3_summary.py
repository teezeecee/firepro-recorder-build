#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_is_wait_bgm_mp3.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_IS_WAIT_BGM_MP3_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052BD","0x0032344C","000002")
assert (m["code_size"],m["body_hex"],m["code_sha256"])==(2,"172a","3e652f9ec0ddcdd64c52c9cba261a1f70bba3ffa41ff4296d6eba45e6514b378")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(2,0,0)
o=s["dll"]["direct_reference_observation"]
assert o["count"]==1 and o["relationship_status"]=="RAW_REFERENCE_ONLY_CALLER_NOT_CLOSED"
assert o["caller"]["token"]=="0x06002ACB"
assert o["caller"]["call_il"]=="0x0267"
print("DLL MENU SOUND IS WAIT BGM MP3 SUMMARY: PASS")
