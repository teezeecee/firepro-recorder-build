"""FACT-0313: original DLCChecker IsOwner and IsValidDLCID source summary."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/dlc_checker_is_owner_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0313-dlc-checker-is-owner-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert f["fact_id"]=="FACT-0313" and f["status"]=="PROVEN_DLL"
assert (w["dataset_id"],w["source_ids"])==("DLL_DLC_CHECKER_IS_OWNER_SOURCE_V1",["DLL-001"])
assert [(m["token"],m["body_length"]) for m in w["methods"]]==[("0x06001032",13),("0x06001033",39)]
for m in w["methods"]:
    body=bytes.fromhex(m["body_hex"])
    assert len(body)==m["body_length"] and hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert [(r["token"],r["name"]) for r in w["memberrefs"]]==[("0x0A0006C4",".ctor"),("0x0A0006C5","BIsSubscribedApp")]
assert (w["exception_section"]["clause"]["try_offset"],w["exception_section"]["clause"]["try_length"])==(15,14)
assert [(c["caller"],[(x["target"],x["sites"]) for x in c["callees"]]) for c in w["direct_callers"]]==[("0x0600103D",[("0x06001032",[18]),("0x06001033",[34])]),("0x060051C9",[("0x06001033",[1])])]
assert len(reg["families"])>=312
assert len(reg["families"])==len(set(family["family_id"] for family in reg["families"]))
assert sum(q["fact_id"]=="FACT-0313" for q in reg["families"])==1
assert next(q for q in reg["families"] if q["fact_id"]=="FACT-0313")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC CHECKER IS OWNER SOURCE SUMMARY: PASS")
