"""FACT-0318 byte-pinned original DLCInstall.Install and branch summary."""
import hashlib,struct,json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/CAP-R6-001/dlc_install_install_source.summary.json").read_text(encoding="utf-8"))
f=json.loads((R/"canonical/facts/FACT-0318-dlc-install-install-source.json").read_text(encoding="utf-8"))
reg=json.loads((R/"canonical/transition_registry.json").read_text(encoding="utf-8"))
assert f["fact_id"]=="FACT-0318" and f["status"]=="PROVEN_DLL"
assert w["dataset_id"]=="DLL_DLC_INSTALL_INSTALL_SOURCE_V1" and w["source_ids"]==["DLL-001"]
m=w["method"];il=bytes.fromhex(m["body_hex"])
assert m["token"]=="0x0600103C" and m["owner"]=="DLCInstall" and len(il)==242
assert hashlib.sha256(il).hexdigest()==m["body_sha256"]
assert len(w["fields"])==5 and len(w["callees"])==4
assert sum(len(c["sites"]) for c in w["callees"])==7
assert [(c["owner"],c["name"]) for c in w["callees"][-2:]]==[("DLCInitializer","AddDLCPromotersAndStables"),("DLCInitializer","AddDLCWrestlers")]
for x in w["fields"]:
    i=x["site"];assert il[i:i+5]==bytes([int(x["opcode"],16)])+struct.pack("<I",int(x["token"],16))
for c in w["callees"]:
    pat=bytes([int(c["opcode"],16)])+struct.pack("<I",int(c["token"],16))
    assert [i for i in range(len(il)-4) if il[i:i+5]==pat]==c["sites"]
for br in w["conditional_branches"]+w["common_target_branches"]:
    i=br["site"];assert il[i]==int(br["opcode"],16)
    assert i+5+struct.unpack_from("<i",il,i+1)[0]==br["target"]
sw=w["switch"];i=sw["site"];n=struct.unpack_from("<I",il,i+1)[0];end=i+5+4*n
assert n==13 and il[i]==0x45 and end==162
assert [end+struct.unpack_from("<i",il,i+5+4*k)[0] for k in range(n)]==sw["targets"]
assert il[w["source_tail"]["start"]:].hex()==w["source_tail"]["hex"]
assert len(reg["families"])>=317 and reg["runtime_unlocked"] is False
ids=[x["family_id"] for x in reg["families"]];facts=[x["fact_id"] for x in reg["families"]]
assert len(ids)==len(set(ids)) and len(facts)==len(set(facts))
assert sum(x=="FACT-0318" for x in facts)==1
assert next(x for x in reg["families"] if x["fact_id"]=="FACT-0318")["runtime_eligible"] is False
print("DLC INSTALL INSTALL SOURCE SUMMARY: PASS")
