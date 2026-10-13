"""FACT-0306: raw original IL witness and append-safe locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_get_skill_filter_name_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0306-skill-info-manager-get-skill-filter-name-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["body_hex"])
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_GET_SKILL_FILTER_NAME_SOURCE_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0306","PROVEN_DLL")
assert m["token"]=="0x06001168" and m["name"]=="GetSkillFilterName"
assert len(body)==m["body_length"]==54 and hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert [(x["site"],x["target"]) for x in [w["branch"]]]==[(13,31)]
assert [x["token"] for x in w["fields"]]==["0x040064EC","0x04000ED8","0x040064F2","0x040064CF"]
assert [(x["token"],x["sites"]) for x in w["memberrefs"]]==[("0x0A000006",[8]),("0x0A000669",[25,48])]
assert w["caller"]["token"]=="0x060029E7" and w["caller"]["call_site"]==427
assert sum(x["fact_id"]=="FACT-0306" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=305
assert reg["runtime_unlocked"] is False
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0306")["runtime_eligible"] is False
print("SKILL INFO MANAGER GET SKILL FILTER NAME SOURCE SUMMARY: PASS")
