"""FACT-0295 static original-DLL source witness and runtime-lock guard."""
import json, collections
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_skill_param_full_il.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0295-skill-info-manager-parse-skill-param-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert f["fact_id"]=="FACT-0295" and f["status"]=="PROVEN_DLL"
assert w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_PARSE_SKILL_PARAM_FULL_IL_V1"
assert w["method"]["token"]=="0x06001153"
assert (w["method"]["bytes"],w["counts"]["direct_calls"])==(1396,47)
assert (w["counts"]["field_writes"],w["counts"]["field_reads"],w["counts"]["warning_ldstr"])==(46,20,35)
assert sum(w["calls"].values())==47 and w["calls"]["0x06001158"]==18 and w["calls"]["0x06001159"]==17
assert w["eh"]["catch_name"]=="System.Object" and w["source_parent"]["token"]=="0x06001152"
assert w["dll"]["sha256"]==w["original_dll_sha"] if "original_dll_sha" in w else w["dll"]["size_bytes"]==8171008
assert sum(x["fact_id"]=="FACT-0295" for x in reg["families"])==1
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("SKILL INFO MANAGER PARSE SKILL PARAM FULL IL SUMMARY: PASS")
