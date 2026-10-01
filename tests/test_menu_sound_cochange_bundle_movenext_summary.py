#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_cochange_bundle_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_COCHANGE_BUNDLE_MOVENEXT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060074F0","0x00324D5C","200002")
assert (m["code_size"],m["code_sha256"])==(248,"e52c9533e53cc4ced4f3643da73e1e997b793257adba26adbc42fa9c4e834754")
assert (m["max_stack"],m["local_signature_token"],m["local_signature_blob_hex"])==(2,"0x1100121C","0702091249")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(75,9,13)
assert s["dll"]["calls"]["load_from_file_async"]["token"]=="0x0A000FAB"
assert s["dll"]["calls"]["get_asset_bundle"]["call_ils"]==["0x0071","0x0087","0x00B5"]
assert s["dll"]["calls"]["audio_clip_set"]["call_il"]=="0x00AA"
assert s["dll"]["calls"]["asset_bundle_unload"]["call_il"]=="0x00BB"
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0021"},{"raw_state":1,"target_il":"0x005B"}]
print("DLL MENU SOUND COCHANGE BUNDLE MOVENEXT SUMMARY: PASS")
