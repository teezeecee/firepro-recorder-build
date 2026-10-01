#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"theme_music_info_check_validation_dlc.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_THEME_MUSIC_INFO_CHECK_VALIDATION_DLC_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x06001191","0x0006CA54","200002")
assert (m["code_size"],m["code_sha256"])==(132,"f49006bbea8bcc23f4ac9019fc646d7fd2dc09edad531bc204b027a920bcc8c2")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(50,11,4)
assert s["dll"]["raw_scan_range"]=={"minimum":0,"maximum":12,"exclusive_upper_bound":13}
assert s["dll"]["raw_special_index"]==9
assert s["dll"]["raw_story_value"]==2
assert s["dll"]["calls"]["is_dlc"]["fact_id"]=="FACT-0114"
assert s["dll"]["calls"]["get_story_data"]["fact_id"]=="FACT-0104"
assert s["dll"]["calls"]["is_dlc_installed"]["token"]=="0x060051C9"
assert s["dll"]["calls"]["is_story_mode"]["token"]=="0x06001FC1"
assert s["dll"]["fact_0111_bridge"]["call_il"]=="0x0025"
print("DLL THEME MUSIC INFO CHECK VALIDATION DLC SUMMARY: PASS")
