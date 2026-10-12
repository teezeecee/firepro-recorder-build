"""FACT-0296: exact original source-only Parse_Flag summary."""
import json,hashlib
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_flag_literal.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0296-skill-info-manager-parse-flag-literal.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["il_hex"])
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_FLAG_LITERAL_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0296","PROVEN_DLL")
assert (m["token"],m["code_bytes"],m["tiny_header"])==("0x06001159",33,"86")
assert len(body)==m["code_bytes"] and hashlib.sha256(body).hexdigest()==m["code_sha256"]
assert m["signature"]=="0002020e0e"
assert w["literal"]["source_text"]=="0" and w["literal"]["unpacked_payload_hex"]=="300000"
assert [(x["offset"],x["target"]) for x in w["branches"]]==[(6,13),(24,31)]
assert len(w["members"])==2 and {x["name"] for x in w["members"]}=={"IsNullOrEmpty","Equals"}
assert len(w["parent"]["call_sites"])==17 and len(set(w["parent"]["call_sites"]))==17
assert sum(x["fact_id"]=="FACT-0296" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER PARSE FLAG LITERAL SUMMARY: PASS")
