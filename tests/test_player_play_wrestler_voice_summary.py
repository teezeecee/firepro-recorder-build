#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_play_wrestler_voice.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_PLAY_WRESTLER_VOICE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06004EB4","0x002DE53C","200001")
assert (m["code_size"],m["code_sha256"])==(272,"827f27896099f2fabf61cc8659bb91cfd1ef7c2cccee142cd3e754ba3e577d8d")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(4,"0x11001063","070312a788081287bc")
assert s["dll"]["calls"]["play_wrestler_voice_leaf"]["token"]=="0x060052B1"
assert s["dll"]["calls"]["play_wrestler_voice_leaf"]["status"]=="BODY_NOT_YET_CANONICAL"
r=s["dll"]["inbound_direct_reference"]
assert (r["canonical_fact"],r["call_il"],r["dll_raw_token_occurrence_count"])==("FACT-0015","0x008E",1)
print("DLL PLAYER PLAY WRESTLER VOICE SUMMARY: PASS")
