"""FACT-0302: source witness identity, original IL byte hash and locked registry."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_parse_filtering_type_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0302-skill-info-manager-parse-filtering-type-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
m=w["method"];body=bytes.fromhex(m["body_hex"])
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_PARSE_FILTERING_TYPE_SOURCE_V1",["DLL-001"])
assert (f["fact_id"],f["status"])==("FACT-0302","PROVEN_DLL")
assert m["token"]=="0x0600115B" and m["name"]=="Parse_FilteringType" and m["body_length"]==74
assert len(body)==74 and hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert [(x["start"],x["length"],x["call_site"]) for x in w["substring_windows"]]==[(2,1,17),(0,2,45)]
assert [(x["site"],x["target"]) for x in w["branches"]]==[(6,14),(32,40),(58,72),(67,72)]
assert [x["site"] for x in w["memberrefs"]]==[1,17,27,45,50]
assert w["literal"]["value"]==" " and w["returns"]["fallback_ordinal"]==38
assert w["exception"]["try_offset"]==42 and w["exception"]["handler_offset"]==63
assert w["parent"]["direct_call_sites"]==[188]
assert sum(x["fact_id"]=="FACT-0302" for x in reg["families"])==1
assert len(reg["families"])==len({x["family_id"] for x in reg["families"]})>=301
assert reg["runtime_unlocked"] is False and reg["families"][-1]["runtime_eligible"] is False
print("SKILL INFO MANAGER FILTERING TYPE SOURCE SUMMARY: PASS")
