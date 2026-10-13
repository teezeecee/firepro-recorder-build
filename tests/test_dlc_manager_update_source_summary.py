"""FACT-0316 DLCManager.Update original byte summary and append-safe source family."""
import hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/CAP-R6-001/dlc_manager_update_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((ROOT/"canonical/facts/FACT-0316-dlc-manager-update-source.json").read_text(encoding="utf-8"))
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert (f["fact_id"],f["status"])==("FACT-0316","PROVEN_DLL")
assert (w["dataset_id"],w["source_ids"])==("DLL_DLC_MANAGER_UPDATE_SOURCE_V1",["DLL-001"])
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert m["token"]=="0x0600103D" and m["owner"]=="DLCManager" and len(il)==114
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert [(x["name"],x["site"]) for x in w["fields"]]==[("DLCNums",0),("inst",77),("dlcVersion",82)]
for x in w["fields"]:
    i=x["site"];assert il[i:i+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["token"],16))
assert [(x["name"],x["site"]) for x in w["callees"]]==[("IsValidDLCID",18),("IsOwner",34),("IsDownloaded",45),("IsInstalled",56),("Install",67),("UnInstall",95)]
assert [(x["name"],x["owner"]) for x in w["callees"][-2:]]==[("Install","DLCInstall"),("UnInstall","DLCUninstall")]
for x in w["callees"]:
    i=x["site"];assert il[i:i+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["token"],16))
for x in w["branches"]:
    i=x["site"];assert il[i]==int(x["opcode"],16)
    assert i+5+struct.unpack_from("<i",il,i+1)[0]==x["target"]
assert [(b["site"],b["target"]) for b in w["branches"]][-1]==(108,13)
families=reg["families"];ids=[x["family_id"] for x in families];facts=[x["fact_id"] for x in families]
assert len(families)>=315 and len(ids)==len(set(ids)) and len(facts)==len(set(facts))
assert sum(x=="FACT-0316" for x in facts)==1
assert next(x for x in families if x["fact_id"]=="FACT-0316")["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
print("DLC MANAGER UPDATE SOURCE SUMMARY: PASS")
