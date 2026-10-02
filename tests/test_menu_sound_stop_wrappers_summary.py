#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_stop_wrappers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_STOP_WRAPPERS_V1"
assert s["dll"]["shared"]["callee"]["fact_id"]=="FACT-0125"
assert s["dll"]["shared"]["local_signature_token"]=="0x1100120B"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060052AE","0x00322E78",15,"bd09c857a08a9f181430706d332d7fc7b542cbc2ab2f270573532874cfc8f92c"),
 ("0x060052B5","0x003230A8",15,"71081b697f7337a53855cbe29050aca01c20cb62f8efbd862eeb4772aa565100")]
assert m[0]["selection"]=="audioSrcInfo[raw 7]"
assert m[1]["parameters"]==[{"sequence":1,"name":"slot","type":"AudioSrcEnum","type_token":"0x02000A88"}]
assert all(x["call_il"]=="0x0009" for x in m)
print("DLL MENU SOUND STOP WRAPPERS SUMMARY: PASS")
