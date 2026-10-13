"""FACT-0300: exact source witness summary and locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_attack_defense_param_parser_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0300-skill-info-manager-attack-defense-param-parser-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
body=bytes.fromhex(w["body"]["hex"])
assert f["fact_id"]=="FACT-0300" and f["status"]=="PROVEN_DLL"
assert w["dataset_id"]=="DLL_SKILL_INFO_MANAGER_ATTACK_DEFENSE_PARAM_SHARED_IL_V1"
assert w["source_ids"]==["DLL-001"]
assert len(body)==71 and hashlib.sha256(body).hexdigest()==w["body"]["sha256"]
assert [x["token"] for x in w["methods"]]==["0x0600115E","0x0600115F"]
assert [x["parent_call_sites"] for x in w["methods"]]==[[280,298],[316,334]]
assert len({x["signature"] for x in w["methods"]})==2
assert w["exception"]["try_offset"]==40
assert w["sibling"]["fact_id"]=="FACT-0298"
assert sum(x["fact_id"]=="FACT-0300" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert reg["runtime_unlocked"] is False
assert reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO ATTACK DEFENSE PARAM PARSER SUMMARY: PASS")
