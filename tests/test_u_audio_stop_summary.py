#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"u_audio_stop.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_U_AUDIO_STOP_V1"
assert s["dll"]["methoddef_row"]=={"token":"0x060052EA","row_hex":"0c5e32000000e601280a04005c4800005f3d","rva":"0x00325E0C"}
m=s["dll"]["method"]
assert (m["code_size"],m["code_sha256"],m["body_hex"])==(18,"d5e285b4ad9285059afee97848d43a163c62ba65523f54379a5d5b6c8248a513","027be987000439060000000228e65200062a")
assert (m["instruction_count"],m["branch_instruction_count"],m["call_instruction_count"])==(7,1,1)
assert s["dll"]["field"]["token"]=="0x040087E9"
assert s["dll"]["call"]=={"token":"0x060052E6","name":"SongEnd","fact_id":"FACT-0126","call_il":"0x000C"}
assert s["dll"]["direct_methoddef_reference_scan"]["all_counts_zero"] is True
print("DLL U AUDIO STOP SUMMARY: PASS")
