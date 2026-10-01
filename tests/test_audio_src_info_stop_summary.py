#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"audio_src_info_stop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_AUDIO_SRC_INFO_STOP_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060052C4","0x00323806","200001")
assert (m["code_size"],m["code_sha256"])==(43,"6367793f54b558ae8629023c6246cc6a97b366e8e4cf5761be3343d3cafcb76a")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(15,1,2)
assert s["dll"]["fields"]["source"]["token"]=="0x0400874C"
assert s["dll"]["fields"]["fade_out_cnt"]["token"]=="0x0400874D"
assert s["dll"]["fields"]["fade_out_frm"]["token"]=="0x0400874E"
assert s["dll"]["calls"]["audio_source_stop"]["token"]=="0x0A00079F"
assert s["dll"]["fact_0123_bridge"]["call_il"]=="0x0009"
print("DLL AUDIO SRC INFO STOP SUMMARY: PASS")
