#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_playing_queries.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_PLAYING_QUERIES_V1"
assert s["dll"]["shared"]["audio_src_info_field"]["token"]=="0x040086EB"
assert s["dll"]["shared"]["source_field"]["token"]=="0x0400874C"
assert s["dll"]["shared"]["get_is_playing"]["token"]=="0x0A000CAE"
m=s["dll"]["methods"]
assert [(x["token"],x["rva"],x["code_size"],x["raw_audio_src_info_index"]) for x in m]==[
 ("0x060052A0","0x00322908",20,0),("0x060052AA","0x00322CA0",20,4)]
assert [x["code_sha256"] for x in m]==[
 "f443c2451dd1f05f72b0fdf52010f2bdf11af076ba3d8cd82f5d819114b82b62",
 "73b973ba207b6764e96da5c8b6513177be2d821c9f0bbbdf234ebd4d13290b2c"]
assert all((x["max_stack"],x["local_signature_token"],x["instruction_count"],x["branch_instruction_count"],x["call_instruction_count"])==(2,"0x1100120B",8,0,1) for x in m)
obs=s["dll"]["raw_caller_observations"]
assert [(x["caller_token"],x["call_il"],x["relationship_status"]) for x in obs]==[
 ("0x0600507F","0x041F","RAW_DIRECT_REFERENCE_CALLER_BODY_NOT_CLOSED_HERE"),
 ("0x060026A4","0x007D","RAW_DIRECT_REFERENCE_CALLER_BODY_NOT_CLOSED_HERE")]
print("DLL MENU SOUND PLAYING QUERIES SUMMARY: PASS")
