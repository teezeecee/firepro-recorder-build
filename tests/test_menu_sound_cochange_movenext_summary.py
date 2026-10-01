#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_cochange_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_COCHANGE_MOVENEXT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["signature_blob_hex"])==("0x060074EA","0x00324C5C","200002")
assert (m["code_size"],m["code_sha256"])==(196,"9d1407458612aaaf641a3eb39d593c95ae61e1e459a85eaa9240647a95763a1f")
assert (m["max_stack"],m["local_signature_token"])==(2,"0x11000047")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(59,8,6)
assert s["dll"]["state_switch"]["targets"]==[{"raw_state":0,"target_il":"0x0021"},{"raw_state":1,"target_il":"0x005B"}]
assert s["dll"]["fields"]["pc"]["token"]=="0x0400C244"
assert s["dll"]["fields"]["audio_clip"]["token"]=="0x0400874B"
assert s["dll"]["calls"]["play_bgm"]["token"]=="0x0600529E"
assert s["dll"]["canonical_relationships"]["factory"]["fact_id"]=="FACT-0115"
assert s["dll"]["canonical_relationships"]["async_caller"]["fact_id"]=="FACT-0129"
print("DLL MENU SOUND COCHANGE MOVENEXT SUMMARY: PASS")
