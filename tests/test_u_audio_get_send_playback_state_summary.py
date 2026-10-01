#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_get_send_playback_state.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_GET_SEND_PLAYBACK_STATE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052CB","0x0032568B","2000151280d1011182b5")
assert (m["code_size"],m["code_sha256"])==(7,"f0eb7b6d2625782d43a08476d93acb464e82bc45c00d660925f2176d82bc8c4b")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(3,0,0)
assert s["dll"]["field"]["token"]=="0x040087E7"
assert s["dll"]["field"]["signature_blob_hex"]=="06151280d1011182b5"
assert [x["call_il"] for x in s["dll"]["fact_0126_bridges"]]==["0x005A","0x0065"]
print("DLL U AUDIO GET SEND PLAYBACK STATE SUMMARY: PASS")
