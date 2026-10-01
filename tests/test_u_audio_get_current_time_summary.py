#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_get_current_time.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_GET_CURRENT_TIME_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052D6","0x00325776","20001182c1")
assert (m["code_size"],m["code_sha256"])==(41,"49f83f2ff33655f9bece0288383a552b4e5a31346d16547fcfd1028ecfdc7b0b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(13,2,1)
assert s["dll"]["fields"]["backend"]["token"]=="0x040087E3"
assert s["dll"]["fields"]["state"]["token"]=="0x040087E9"
assert s["dll"]["fields"]["end_song_time"]["token"]=="0x040087F2"
assert s["dll"]["call"]["token"]=="0x0A000FB8"
assert s["dll"]["fact_0126_bridge"]["call_il"]=="0x0002"
print("DLL U AUDIO GET CURRENT TIME SUMMARY: PASS")
