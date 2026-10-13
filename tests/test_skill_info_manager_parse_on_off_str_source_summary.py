"""FACT-0307: original parser string literals, source IL and append-safe registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_on_off_str_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0307-skill-info-manager-parse-on-off-str-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["body_hex"])
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_ON_OFF_STR_SOURCE_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0307","PROVEN_DLL")
assert (m["token"],m["name"],m["body_length"])==("0x06001157","ParseOnOffStr",67)
assert len(body)==67 and hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert [(x["text"],x["return_ordinal"],x["ldstr_site"]) for x in w["literals"]]==[("0",0,12),("ON",1,30),("OFF",0,48)]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(6,27),(22,29),(40,47),(58,65)]
assert [x["sites"] for x in w["memberrefs"]]==[[1],[17,35,53]]
assert w["caller"]["token"]=="0x0600114C" and w["caller"]["call_sites"]==[206]
assert sum(x["fact_id"]=="FACT-0307" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=306
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0307")["runtime_eligible"] is False
print("SKILL INFO MANAGER PARSE ON OFF STR SOURCE SUMMARY: PASS")
