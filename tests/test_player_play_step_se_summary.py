#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"player_play_step_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_PLAY_STEP_SE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06004EB5","0x002DE658","200001")
assert (m["code_size"],m["code_sha256"])==(171,"efbedac2c1bed8042849458be9e4aab0aff8bbe2e7f42d4ca0a31ce98fd698dc")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(3,"0x11001064","07030c1d11aa0c12a408")
assert s["dll"]["calls"]["range"]["fact_id"]=="FACT-0032"
assert s["dll"]["calls"]["play_match_se"]["fact_id"]=="FACT-0058"
assert s["dll"]["inbound_direct_reference"]["canonical_fact"]=="FACT-0015"
print("DLL PLAYER PLAY STEP SE SUMMARY: PASS")
