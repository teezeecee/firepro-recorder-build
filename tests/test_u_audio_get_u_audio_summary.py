#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_get_u_audio.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_GET_U_AUDIO_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052D0","0x003256D4","20001282b1")
assert (m["code_size"],m["code_sha256"])==(86,"5524703abb8912537cca2bf60cf25fdcde63df8bcc2ea51a0db76d5dc8e858c4")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(25,1,5)
assert s["dll"]["fields"]["backend"]["token"]=="0x040087E3"
assert s["dll"]["calls"]["callback_method"]["token"]=="0x060052EE"
assert s["dll"]["calls"]["callback_delegate_ctor"]["parent_typespec_token"]=="0x1B0002D6"
assert s["dll"]["calls"]["callback_delegate_ctor"]["resolved_parent"]=="System.Action<uAudio.uAudio_backend.PlayBackState>"
assert [x["call_il"] for x in s["dll"]["fact_0137_bridges"]]==["0x0013","0x0035"]
print("DLL U AUDIO GET U AUDIO SUMMARY: PASS")
