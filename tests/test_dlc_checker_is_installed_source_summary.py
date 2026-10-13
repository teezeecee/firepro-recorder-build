"""FACT-0314: exact original DLCChecker.IsInstalled wrapper and registry append."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/dlc_checker_is_installed_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0314-dlc-checker-is-installed-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert (f["fact_id"],f["status"])==("FACT-0314","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_DLC_CHECKER_IS_INSTALLED_SOURCE_V1",["DLL-001"])
assert (w["method"]["token"],w["method"]["name"])==("0x06001035","IsInstalled")
body=bytes.fromhex(w["method"]["body_hex"])
assert len(body)==12 and hashlib.sha256(body).hexdigest()==w["method"]["body_sha256"]
assert body[:5]==bytes([0x7E])+struct.pack("<I",int(w["field"]["token"],16))
assert body[5:6]==bytes([0x02])
assert body[6:11]==bytes([0x6F])+struct.pack("<I",int(w["callee"]["token"],16))
assert body[11:]==bytes([0x2A])
assert w["field"]["name"]=="inst" and w["field"]["owner"]=="SaveData"
assert w["callee"]["name"]=="IsDLCInstalled"
ids=[x["family_id"] for x in reg["families"]]
factids=[x["fact_id"] for x in reg["families"]]
assert len(ids)>=313 and len(ids)==len(set(ids)) and len(factids)==len(set(factids))
assert "FACT-0314" in factids
assert sum(x["fact_id"]=="FACT-0314" for x in reg["families"])==1
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0314")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC CHECKER IS INSTALLED SOURCE SUMMARY: PASS")
