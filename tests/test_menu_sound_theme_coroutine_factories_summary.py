#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_theme_coroutine_factories.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_THEME_COROUTINE_FACTORIES_V1"
sig=s["dll"]["shared_signature"]
assert sig["signature_blob_hex"]=="00041281810e11aa24021280fd"
assert sig["return_type"]=="System.Collections.IEnumerator"
assert sig["parameters"]==[
 {"sequence":1,"name":"fn","type":"String"},
 {"sequence":2,"name":"system_sound","type":"SYSTEM_SOUND"},
 {"sequence":3,"name":"bStart","type":"Boolean"},
 {"sequence":4,"name":"onLoad","type":"System.Action"}]
f=s["dll"]["factories"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in f]==[
 ("0x06005294","0x00322208",36,"6bf3b32bde5c0e41ede808a7df79d384f18e7aa4cb00181ed96c4495a8a69082"),
 ("0x06005295","0x00322238",36,"350a54533b1c76c5c5a5d7259e377d8aa3b1e1cf2aeb16042332cc6aa01bedb5")]
assert all((x["instruction_count"],x["branch_instruction_count"],x["call_instruction_count"])==(16,0,1) for x in f)
ctors=s["dll"]["generated_constructors"]
assert [x["token"] for x in ctors]==["0x060074E9","0x060074EF"]
assert all(x["code_size"]==7 and x["code_sha256"]=="5d00b167bdfbaef5db8274a65cefd86c61b9e10c9a45527597133bf7d8e596e9" for x in ctors)
assert [x["call_il"] for x in s["dll"]["fact_0111_bridges"]]==["0x00A7","0x007E"]
print("DLL MENU SOUND THEME COROUTINE FACTORIES SUMMARY: PASS")
