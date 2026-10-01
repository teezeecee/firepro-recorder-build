#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"mine_presentation_support.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_MINE_PRESENTATION_SUPPORT_V1"
m=s["dll"]["methods"]
assert [(x["token"],x["code_size"],x["code_sha256"]) for x in m]==[
 ("0x06004876",25,"706f9840af6e5fc17181d4522b1d7900ff500e0dd9c657c47a45849fa0a0eb45"),
 ("0x060050E3",8,"f8a8ac1e526882d2d8478bd371f6d9d6027b364f890e507fe69dfc7b9da02623"),
 ("0x06004884",25,"71a69e97e6e16dc6e78a660ef0833d3e5999bf892f194d77054a5c49003dba1c")]
assert s["dll"]["layer_lookup"]["valid_raw_range"]=={"min_inclusive":0,"max_inclusive":8}
assert s["dll"]["ring_shake"]["effect"]=="ShakeCnt = time"
assert s["dll"]["vibration"]["effect"]=="VibPos = 0.05000000074505806f * vib_lv; VibVel = 0.0f"
assert [x["il"] for x in s["dll"]["fact_0056_bridge"]["calls"]]==["0x005D","0x0083","0x0092"]
print("DLL MINE PRESENTATION SUPPORT SUMMARY: PASS")
