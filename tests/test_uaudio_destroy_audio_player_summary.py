#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"uaudio_destroy_audio_player.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_UAUDIO_DESTROY_AUDIO_PLAYER_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052CA","0x0032567D","200001")
assert (m["code_size"],m["code_sha256"])==(13,"62a68c749da17a7c536b2ef155fd300637ffd8bd582da8979c28fdd87bf83d1c")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(5,0,2)
assert s["dll"]["calls"]["song_end"]["call_il"]=="0x0001"
assert s["dll"]["calls"]["unity_destroy"]["call_il"]=="0x0007"
assert s["dll"]["fact_0123_bridge"]["call_il"]=="0x0023"
print("DLL UAUDIO DESTROY AUDIO PLAYER SUMMARY: PASS")
