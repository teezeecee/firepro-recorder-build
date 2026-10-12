"""FACT-0291 source-only ApplySkillParam witness and registry check."""
import json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/skill_info_manager_apply_skill_param_transfers.summary.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0291-skill-info-manager-apply-skill-param-transfers.json").read_text())
r=json.loads((ROOT/"canonical/transition_registry.json").read_text())
d=w["dll"];m=d["method"]
assert (w["dataset_id"],w["source_ids"])==("DLL_SKILL_INFO_MANAGER_APPLY_SKILL_PARAM_TRANSFERS_V1",["DLL-001"])
assert (m["token"],m["code_bytes"],m["code_sha256"])==("0x06001166",386,"49f3fdacd9378d68c7c474766af4ba146ebccc86a8acbb27e240f63353640291")
body=b"".join(bytes.fromhex(x["il_hex"]) for x in d["segments"])
assert len(body)==386 and hashlib.sha256(body).hexdigest()==m["code_sha256"]
assert [len(bytes.fromhex(x["il_hex"])) for x in d["segments"]]==[15,34,336,1]
assert (len(d["fielddefs"]),len(d["transfer_pairs"]),len(d["branches"]))==(58,28,3)
assert all(int(x["end_exclusive_il"],16)-int(x["start_il"],16)==12 for x in d["transfer_pairs"])
assert [x["field_name"] for x in d["transfer_pairs"]][-4:]==["cheerLevel","reversalSkillType","reversalRateType","primarySkillStrength"]
assert [x["target_il"] for x in d["branches"]]==["0x000F","0x002A","0x0016"]
assert d["lookup_call"]["call_hex"]=="2864110006" and d["parent_call"]["call_hex"]=="6f66110006"
assert f["fact_id"]=="FACT-0291" and f["status"]=="PROVEN_DLL"
assert sum(x["fact_id"]=="FACT-0291" for x in r["families"])==1
assert len({x["family_id"] for x in r["families"]})==len(r["families"])
print("SKILL INFO MANAGER APPLY SKILL PARAM TRANSFERS SUMMARY: PASS")
