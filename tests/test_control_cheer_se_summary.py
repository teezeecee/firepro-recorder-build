#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"control_cheer_se.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_PLAYER_CONTROL_CHEER_SE_V1"
m=s["dll"]["method"]
assert m["token"]=="0x06004EBF" and m["rva"]=="0x002DED38"
assert m["signature_blob_hex"]=="200001" and m["parameters"]==[]
assert m["code_size"]==225
assert m["code_sha256"]=="9f48dfc674cd2b0e1bfde5d807f76c9410dfadf6bf13d0e3fe8a1da481dcf6ce"
assert s["dll"]["entry_gates"][1]["raw_mask"]==2
assert s["dll"]["adjustment_tree"][0]["raw_add"]==2
assert s["dll"]["adjustment_tree"][1]["raw_add"]==1
assert s["dll"]["adjustment_tree"][2]["raw_divisor"]==2
assert s["dll"]["final_level_filter"][1]["raw_cap"]==4
assert s["dll"]["audience_dispatch"]["calls"][0]["token"]=="0x060047DA"
assert s["dll"]["audience_dispatch"]["calls"][1]["token"]=="0x060047D9"
assert s["dll"]["update_animation_bridge"]["fact_id"]=="FACT-0014"
assert s["dll"]["form_query_bridge"]["fact_id"]=="FACT-0017"
print("DLL CONTROL CHEER SE SUMMARY: PASS")
