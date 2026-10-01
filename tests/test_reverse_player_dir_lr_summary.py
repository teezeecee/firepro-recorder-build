#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"reverse_player_dir_lr.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_REVERSE_PLAYER_DIR_LR_V1"
m=s["dll"]["method"]
assert (m["token"],m["rva"],m["code_size"],m["code_sha256"])==("0x06004966","0x002B0428",8,"c361809e798508defe998c0c3891196cdb2d60d5f4e45adf6fc213666c309eb0")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(4,0,0)
assert s["dll"]["table_field"]=={"type":"MatchMisc","name":"rev_lr_tbl","token":"0x04005788","signature_blob_hex":"061d11a768"}
assert s["dll"]["exact_body"]==["ldsfld MatchMisc.rev_lr_tbl","ldarg.0","ldelem.i4","ret"]
assert s["dll"]["fact_0087_bridge"]["call_il"]=="0x003E"
print("DLL REVERSE PLAYER DIR LR SUMMARY: PASS")
