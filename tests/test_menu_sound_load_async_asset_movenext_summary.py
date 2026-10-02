#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"menu_sound_load_async_asset_movenext.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MENU_SOUND_LOAD_ASYNC_ASSET_MOVENEXT_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x060074C0","0x00323A60",147,"a4d0aab998a3a51651ad2a7266627226a911274f84e12043ba419b6a5325cff7")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(46,7,4)
assert s["dll"]["state_switch"]=={"raw_state_0_target":"0x0021","raw_state_1_target":"0x0057","default_target":"0x008F"}
e=s["dll"]["external_members"]
assert e["resources_load_async"]["call_il"]=="0x0028"
assert e["async_is_done"]["call_il"]=="0x005D"
assert e["resource_get_asset"]["call_il"]=="0x007E"
assert e["callback_invoke"]["call_il"]=="0x0083"
assert s["dll"]["fact_0167_metadata_relationship"]["relationship_status"]=="FACTORY_GENERATED_TYPE_OWNERSHIP_NOT_RUNTIME_CALL"
print("DLL MENU SOUND LOAD ASYNC ASSET MOVENEXT SUMMARY: PASS")
