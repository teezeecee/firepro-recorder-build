#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"cheer_loop_playback.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_CHEER_LOOP_PLAYBACK_V1"
a,b=s["dll"]["methods"]
assert (a["token"],a["code_size"],a["code_sha256"])==("0x060052AD",158,"001cb4d3bd5417613100f8bfe639e04dda3482b57c57eb21ef6522ce30adfebe")
assert (a["instruction_count"],a["branch_instruction_count"],a["call_instruction_count"])==(61,7,6)
assert (b["token"],b["code_size"],b["code_sha256"])==("0x060052B0",76,"6f321c7c744fbfc0c24a57378d548aa080b210e4d264ec0cf63d9c9576338126")
assert (b["instruction_count"],b["branch_instruction_count"],b["call_instruction_count"])==(28,3,2)
assert s["dll"]["shared"]["audio_src_info_index"]==7
assert s["dll"]["play_loop"]["valid_vid_range"]=={"min_inclusive":0,"max_inclusive":41}
assert s["dll"]["play_loop"]["tail_writes"]==[{"field":"fadeOutFrm","token":"0x0400874E","value":0},{"field":"fadeOutCnt","token":"0x0400874D","value":0}]
assert [x["il"] for x in s["dll"]["fact_0081_bridge"]["calls"]]==["0x00FA","0x010E"]
print("DLL CHEER LOOP PLAYBACK SUMMARY: PASS")
