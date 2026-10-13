"""FACT-0315 original DLCChecker.IsDownloaded source-summary audit."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/dlc_checker_is_downloaded_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0315-dlc-checker-is-downloaded-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert f["fact_id"]=="FACT-0315" and f["status"]=="PROVEN_DLL"
assert w["dataset_id"]=="DLL_DLC_CHECKER_IS_DOWNLOADED_SOURCE_V1" and w["source_ids"]==["DLL-001"]
m=w["method"];body=bytes.fromhex(m["body_hex"])
assert m["token"]=="0x06001034" and len(body)==17
assert hashlib.sha256(body).hexdigest()==m["body_sha256"]
assert body[0]==2 and body[16]==42
assert body[1:6]==bytes([0x28])+struct.pack("<I",int(w["methoddef_callee"]["token"],16))
assert body[6:11]==bytes([0x73])+struct.pack("<I",int(w["memberrefs"][0]["token"],16))
assert body[11:16]==bytes([0x28])+struct.pack("<I",int(w["memberrefs"][1]["token"],16))
assert w["memberrefs"][1]["name"]=="BIsDlcInstalled"
assert w["direct_caller"]["site"]==45
families=reg["families"];ids=[x["family_id"] for x in families];facts=[x["fact_id"] for x in families]
assert len(families)>=314 and len(ids)==len(set(ids)) and len(facts)==len(set(facts))
assert "FACT-0315" in facts and sum(x=="FACT-0315" for x in facts)==1
assert next(x for x in families if x["fact_id"]=="FACT-0315")["runtime_eligible"] is False and reg["runtime_unlocked"] is False
print("DLC CHECKER IS DOWNLOADED SOURCE SUMMARY: PASS")
