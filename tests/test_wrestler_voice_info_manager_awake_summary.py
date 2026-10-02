#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_manager_awake.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_MANAGER_AWAKE_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060011E6","0x0006F11E","200001")
assert (m["code_size"],m["code_sha256"])==(61,"bcee56df40b0e166d956e871a4b165a2e11eed714129aff4e22590ffbe441aae")
assert s["dll"]["fields"]["inst"]["token"]=="0x040011E6"
assert s["dll"]["fields"]["fallback"]["token"]=="0x040011E8"
assert s["dll"]["user_string"]=={"token":"0x70007D32","value":"Unknown","load_ils":["0x0012","0x0024"]}
assert s["dll"]["direct_call"]=={"token":"0x060011EA","resolved":"WrestlerVoiceInfoManager.Parse","call_il":"0x0037","callee_status":"OPEN"}
assert s["dll"]["direct_awake_reference_scan"]["all_counts_zero"] is True
print("DLL WRESTLER VOICE INFO MANAGER AWAKE SUMMARY: PASS")
