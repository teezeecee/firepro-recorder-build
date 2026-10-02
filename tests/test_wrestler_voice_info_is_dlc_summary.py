#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"wrestler_voice_info_is_dlc.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_WRESTLER_VOICE_INFO_IS_DLC_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060011E4","row_hex":"d0f00600000086006f7d0800db490000a00d","rva":"0x0006F0D0"}
m=s["dll"]["method"]
assert (m["signature_blob_hex"],m["code_size"],m["code_sha256"])==("200002",36,"2acb70b4c1485d922c4cb298c85655aced949090d9446da112ff0935df31c9f6")
assert (m["header_flags_raw"],m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==("0x0013",2,"0x1100003A","070108")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(19,3,0)
assert s["dll"]["field"]=={"token":"0x040011DE","name":"dlc","signature_blob_hex":"061d02","type":"Boolean[]"}
assert s["dll"]["fact_0178_bridge"]=={"fact_id":"FACT-0178","caller":"<LoadAsync_WrestlerVoiceList>c__Iterator3.MoveNext","call_il":"0x01BF","callee_token":"0x060011E4"}
print("DLL WRESTLER VOICE INFO IS DLC SUMMARY: PASS")
