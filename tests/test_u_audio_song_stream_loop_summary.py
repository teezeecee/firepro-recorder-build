#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_song_stream_loop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_SONG_STREAM_LOOP_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052E8","row_hex":"f45c32000000810013640a00c3e502005e3d","rva":"0x00325CF4"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"])==(73,"2834d930fa5659f589d893b94877b0b1b3462054322124cc7e1124abb3e8ae39")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(29,5,1)
assert s["dll"]["fields"]["source_destroy"]["token"]=="0x040087E8"
assert s["dll"]["call"]["token"]=="0x0A000FD4"
eh=s["dll"]["exception_section"]
assert (eh["size_bytes"],eh["sha256"])==(16,"6a80fae31f6fc3bf241bdd460e4208a9fd322a555b82a612da16d0b82c9adab2")
assert eh["clause"]["class_token"]=="0x010000D2"
assert s["dll"]["fact_0140_bridge"]["ldftn_il"]=="0x0070"
print("DLL U AUDIO SONG STREAM LOOP SUMMARY: PASS")
