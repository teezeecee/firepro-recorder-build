#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_play_wrestler_voice.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_PLAY_WRESTLER_VOICE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052B1","0x00322F34","00030108080c")
assert (m["code_size"],m["code_sha256"])==(125,"89b773f755d9066b9ae0731733012e2c12839acab2548a261e022dbf7b158c12")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(3,"0x1100120F","070412490c12aa2c1280b9")
assert s["dll"]["fields"]["clips"]["type"]=="UnityEngine.AudioClip[,]"
assert s["dll"]["calls"]["audio_source_play_one_shot"]["call_il"]=="0x0077"
r=s["dll"]["inbound_direct_reference"]
assert (r["canonical_fact"],r["call_il"],r["callee_token"])==("FACT-0187","0x00B8","0x060052B1")
print("DLL MENU SOUND PLAY WRESTLER VOICE SUMMARY: PASS")
