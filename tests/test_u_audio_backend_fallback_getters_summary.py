#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_backend_fallback_getters.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_BACKEND_FALLBACK_GETTERS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052D5","0x00325758",29,"c90322aba94a9bdb71409ad82330912a9b3749566383217b56951c45c2a42293"),
 ("0x060052DA","0x003257FC",29,"c2d0be581347b6907ae28115746372eaad0f60669f9234113bc3e38abfbd3994")]
assert m[0]["backend_call"]=={"token":"0x0A000FB7","resolved":"uAudio.uAudio_backend.uAudio.get_AudioTitle","call_il":"0x0011"}
assert m[0]["fallback"]=={"token":"0x0A000025","resolved":"System.String.Empty","load_il":"0x0017"}
assert m[1]["backend_call"]=={"token":"0x0A000FBC","resolved":"uAudio.uAudio_backend.uAudio.get_TotalTime","call_il":"0x0011"}
assert m[1]["fallback"]=={"token":"0x0A000FBD","resolved":"System.TimeSpan.Zero","load_il":"0x0017"}
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO BACKEND FALLBACK GETTERS SUMMARY: PASS")
