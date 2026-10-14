"""FACT-0324 original Unity source complete TimeManager object witness regression."""
import hashlib,json,struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/time_manager_four_timestep_fields.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0324-original-unity-time-manager.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
assert w["dataset_id"]=="UNITY_TIMEMANAGER_FOUR_TIMESTEP_SOURCE_V1" and w["source_ids"]==["GGM-001"]
assert (f["fact_id"],f["status"])==("FACT-0324","PROVEN_PACKED_DATA")
source=next(s for s in m["sources"] if s["source_id"]=="GGM-001")
assert source["sha256"]==w["source_file"]["sha256"] and source["canonical_eligible"] is True
o=w["object"];raw=bytes.fromhex(o["hex"])
assert (o["class_id"],o["type_index"],o["path_id"],o["absolute_offset"],len(raw))==(5,7,8,0x10518,16)
assert hashlib.sha256(raw).hexdigest()==o["sha256"]
fields=w["fields"]
assert len(fields)==4
assert [q["offset"] for q in fields]==[0,4,8,12]
assert [q["raw_hex"] for q in fields]==[raw[i:i+4].hex() for i in (0,4,8,12)]
assert [q["float32"] for q in fields]==list(struct.unpack("<4f",raw))
assert fields[2]["float32"]==1.0 and fields[0]["float32"]<0.021 and fields[0]["float32"]>0.019
match=[x for x in reg["families"] if x["fact_id"]=="FACT-0324"]
assert len(match)==1 and match[0]["family_id"]==w["dataset_id"] and match[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("GLOBALGAMEMANAGERS ORIGINAL TIME MANAGER SOURCE SUMMARY: PASS")
