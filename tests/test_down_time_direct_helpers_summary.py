#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"down_time_direct_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_DOWN_TIME_DIRECT_HELPERS_V1"
ms={m["name"]:m for m in s["dll"]["methods"]}
assert (ms["SetStunTime"]["code_size"],ms["SetStunTime"]["code_sha256"])==(27,"f1cf347336997ae6ca3fc68973801bfad9697cf43326c86143a6cfa7cbb96074")
assert (ms["GetParamRate"]["code_size"],ms["GetParamRate"]["code_sha256"])==(16,"60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c")
assert s["dll"]["set_stun_time"]["clamp_continue_opcode"]=="bge"
assert s["dll"]["get_param_rate"]["raw_divisor"]==65535.0 and s["dll"]["get_param_rate"]["raw_multiplier"]==100.0
assert s["dll"]["calc_down_time_bridge"]["fact_id"]=="FACT-0030"
print("DLL DOWN TIME DIRECT HELPERS SUMMARY: PASS")
