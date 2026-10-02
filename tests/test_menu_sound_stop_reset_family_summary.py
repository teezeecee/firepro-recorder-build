#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_stop_reset_family.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_STOP_RESET_FAMILY_V1"
assert s["dll"]["shared"]["audio_src_info_stop"]=={"token":"0x060052C4","name":"AudioSrcInfo.Stop","fact_id":"FACT-0125"}
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["stop_call_il"]) for x in m]==[
 ("0x060052B2","0x00322FC0",21,"0x000F"),("0x060052B3","0x00322FE4",110,"0x0027"),("0x060052B4","0x00323060",57,"0x0009")]
assert [x["code_sha256"] for x in m]==[
 "49e066c2b1ee1ab65086c2e443f5cb0f8cf3aa35b639aba7646ba87dc609e4c9",
 "4706c335f4923a712dae0e35d839c427459c3268d2fd380435d7bb9bcdca0ff1",
 "0af8b0fc25dd48cd0572ac0c664bf58267f9ef3a3fcb6dae9e3eaaa76ab37bd8"]
assert [(x["instruction_count"],x["branch_instruction_count"],x["call_instruction_count"]) for x in m]==[(9,0,1),(46,8,1),(25,2,1)]
assert len(s["dll"]["raw_caller_observations"])==12
print("DLL MENU SOUND STOP RESET FAMILY SUMMARY: PASS")
