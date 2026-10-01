#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"transit_state_after_anm.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_TRANSIT_STATE_AFTER_ANM_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"],m["code_size"],m["code_sha256"])==(
 "0x06004EC8","0x002E0B8C","200001",1438,"cb9c68b98a1db450cee699fde8a7ab45926cb582dafa5b9e78e51b87d8886bb6")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(446,49,61)
assert s["dll"]["form_info_down_dispatch"]["form_idx_values"]==[100,101]
cases=s["dll"]["switch_cases"]
assert [x["anime_end"] for x in cases]==list(range(1,15))
assert [x["target"] for x in cases]==["0x0172","0x059D","0x02D9","0x0331","0x059D","0x026A","0x01F5","0x0350","0x03A5","0x03B0","0x03C9","0x0418","0x04A8","0x0584"]
assert s["dll"]["auto_run_helper"]["raw_anime_end"]==9
assert s["dll"]["caller_bridge"]["fact_id"]=="FACT-0047"
print("DLL TRANSIT STATE AFTER ANM SUMMARY: PASS")
