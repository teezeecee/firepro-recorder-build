#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/"canonical"/"witnesses"/"CAP-R6-001"/"form_query_helpers.summary.json").read_text(encoding="utf-8"))
assert s["dataset_id"]=="DLL_FORMANIMATOR_FORM_QUERY_HELPERS_V1"
ms={m["method"]:m for m in s["dll"]["methods"]}
assert set(ms)=={"FormAnimator.IsAnmComplete","FormAnimator.IsLastForm","FormAnimator.IsPrevLastAnmFrame","FormAnimator.GetCurrentFormDispInfo"}
assert ms["FormAnimator.IsAnmComplete"]["code_sha256"]=="766907d7d20a39e44a0af0fef66b1d47f6548b29eaa8beba381d29f1d91456c1"
assert ms["FormAnimator.IsLastForm"]["code_sha256"]=="8d7732e16017ba91bf17d733b6602560309e02121b3399203dd52964aa5d1694"
assert ms["FormAnimator.IsPrevLastAnmFrame"]["code_sha256"]=="21448fc69b9fb12146af52cd1fcbb9d21ae7a3069e4647438e91f04380e78627"
assert ms["FormAnimator.GetCurrentFormDispInfo"]["code_sha256"]=="7bb1c23a0880b9ebe1d997e643e069597c94c0784a03e03ba2b9a1ab207045c0"
assert ms["FormAnimator.IsAnmComplete"]["exact_logic"][0]=="if FormDispDuration > 0: return false"
assert ms["FormAnimator.IsPrevLastAnmFrame"]["exact_logic"][0]=="if FormDispDuration > 1: return false"
assert ms["FormAnimator.IsLastForm"]["exact_logic"][-2:] == ["if currentFormIdx == anm.formNum - 1: return true","return false"]
assert ms["FormAnimator.GetCurrentFormDispInfo"]["exact_logic"][-1]=="return anm.formDispList[currentFormIdx]"
assert len(s["dll"]["closed_call_boundaries"])==2
print("DLL FORM QUERY HELPERS SUMMARY: PASS")
