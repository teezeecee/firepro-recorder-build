#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_check_validation_dlc.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_CHECK_VALIDATION_DLC_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060011E3","row_hex":"80f00600000086005c7d0800db490000a00d","rva":"0x0006F080"}
m=s["dll"]["method"]
assert (m["signature_blob_hex"],m["code_size"],m["code_sha256"])==("200002",65,"d6297fd525cdb31260595c4e0a1705c380f1201b6392c91b59d5589ecba0ccc4")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==("0x0013",2,"0x110002DE","07011185c8")
assert m["locals"]==[{"index":0,"type":"DLCEnum","type_token":"0x02000172"}]
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(28,5,2)
assert s["dll"]["calls"]["is_dlc"]=={"token":"0x060011E4","resolved":"WrestlerVoiceInfo.IsDLC","fact_id":"FACT-0179","call_il":"0x0001"}
assert s["dll"]["calls"]["is_dlc_installed"]=={"token":"0x060051C9","resolved":"SaveData.IsDLCInstalled(DLCEnum)","fact_id":"FACT-0119","call_il":"0x0027"}
assert s["dll"]["fact_0178_bridge"]["call_il"]=="0x01CF"
print("DLL WRESTLER VOICE INFO CHECK VALIDATION DLC SUMMARY: PASS")
