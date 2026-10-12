"""FACT-0288 exact original DLL-only witness and registry integrity check."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_data_man_additional_animation_import_route.summary.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0288-skill-data-man-additional-animation-import-route.json").read_text())
d=w["dll"];m=d["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_DATA_MAN_ADDITIONAL_ANIMATION_IMPORT_ROUTE_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x0600525B",267,"f5966ee12b5c4065dcef8f0f00c3832f13a0a600a5914a2452c1f4e116f3506e")
assert [len(bytes.fromhex(x["il_hex"])) for x in d["segments"]]==[51,50,68,46,37,15]
assert hashlib.sha256(b"".join(bytes.fromhex(x["il_hex"]) for x in d["segments"])).hexdigest()==m["code_sha256"]
assert [(x["text"],x["token"]) for x in d["user_strings"].values()]==[("fpw_","0x7008D506"),("_","0x700006E9"),("D1","0x7008D510")]
assert (len(d["fields"]),len(d["memberrefs"]),len(d["methoddef_callees"]),len(d["branches"]))==(4,10,4,8)
assert [x["target_token"] for x in d["source_call_sites"]]==["0x06001164","0x06005244","0x0600525C","0x06001166"]
assert (d["exception_handler"]["flags"],d["exception_handler"]["handler_start_il"],d["exception_handler"]["handler_length"])==(2,"0x00FC",14)
assert (f["fact_id"],f["status"])==("FACT-0288","PROVEN_DLL")
assert sum(x["fact_id"]=="FACT-0288" for x in r["families"])==1
assert sum(x["family_id"]=="DLL_SKILL_DATA_MAN_ADDITIONAL_ANIMATION_IMPORT_ROUTE_V1" for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
print("SKILL DATA MAN ADDITIONAL ANIMATION IMPORT ROUTE SUMMARY: PASS")
