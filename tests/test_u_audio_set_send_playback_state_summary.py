#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_set_send_playback_state.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SET_SEND_PLAYBACK_STATE_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052CC","row_hex":"935632000000e6091c8a070055480100523d","rva":"0x00325693"}
m=s["dll"]["method"]
assert (m["signature_blob_hex"],m["code_size"],m["code_sha256"])==("200101151280d1011182b5",8,"8b12d7dcbce95657c6a5b8f58f76123dbc997c306b7976ba5e8419839add7a29")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,0)
assert s["dll"]["field"]["token"]=="0x040087E7"
assert s["dll"]["paired_getter"]=={"fact_id":"FACT-0127","token":"0x060052CB","field_token":"0x040087E7"}
assert s["dll"]["relationship_status"]=="FIELD_WRITER_WITH_NO_PROMOTED_DIRECT_CALLER"
print("DLL U AUDIO SET SEND PLAYBACK STATE SUMMARY: PASS")
