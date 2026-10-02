#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_construction_defaults.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_CONSTRUCTION_DEFAULTS_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x060011E1","0x0006F013",26,"6836ea693beefcbacf0cca451f7be338d0113f53f4ce8b3710d8cf6b5039039a"),
 ("0x060011E2","0x0006F030",65,"941c4078e31edb844e0a3e59cb5ae28a6dedf8e86b01896fbaacf71c0a699a60"),
 ("0x060011E5","0x0006F100",29,"d73d650906909f5df68b9d1210095d7763ad6ca99a890b3fce2dd6238b6918f7")]
assert s["dll"]["fields"]["dlc"]["token"]=="0x040011DE"
assert s["dll"]["fields"]["wrestlerVoiceInfo"]["token"]=="0x040011E7"
assert s["dll"]["metadata"]["list_wrestler_voice_attr_ctor"]=="0x0A000786"
assert s["dll"]["metadata"]["list_wrestler_voice_info_ctor"]=="0x0A000791"
assert s["dll"]["direct_edge"]=={"caller":"WrestlerVoiceInfoManager..ctor","call_il":"0x000C","opcode":"newobj","callee_token":"0x060011E1","callee":"WrestlerVoiceAttr..ctor"}
print("DLL WRESTLER VOICE CONSTRUCTION DEFAULTS SUMMARY: PASS")
