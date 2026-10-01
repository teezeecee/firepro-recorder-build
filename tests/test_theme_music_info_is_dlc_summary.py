#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"theme_music_info_is_dlc.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_THEME_MUSIC_INFO_IS_DLC_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06001192","0x0006CAE4","200002")
assert (m["code_size"],m["code_sha256"])==(36,"493b5cdc804f432200f9198f85dbd365d62854ee6f944047f0cd690002c2f3cd")
assert (m["max_stack"],m["local_signature_token"])==(2,"0x1100003A")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(19,3,0)
assert s["dll"]["field"]=={"name":"ThemeMusicInfo.dlc","token":"0x04000FB8","signature_blob_hex":"061d02","type":"Boolean[]"}
assert s["dll"]["raw_scan_range"]=={"minimum":0,"maximum":15,"exclusive_upper_bound":16}
assert [x["call_il"] for x in s["dll"]["fact_0111_bridges"]]==["0x0059","0x00B8"]
print("DLL THEME MUSIC INFO IS DLC SUMMARY: PASS")
