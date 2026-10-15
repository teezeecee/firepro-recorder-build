"""FACT-0334 original Unity MonoManager script references and assemblies summary gate."""
import base64,bz2,hashlib,json
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/mono_manager_1613_scripts_13_assemblies.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0334-original-unity-mono-manager.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0334","PROVEN_PACKED_DATA",[])
src=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["absolute_offset"],o["relative_offset"],o["bytes"])==(116,5,6,0xB608,42504,19672)
p=w["script_reference_table"];a=w["script_references_archive"];data=bz2.decompress(base64.b64decode(a["data"]))
assert (len(data),hashlib.sha256(data).hexdigest())==(13450,"80901fe9813cfebd3fe7a976fa2d2a6d53280ed1459222171872a54030b06ec6")
rows=json.loads(data)
assert len(rows)==p["count"]==1613 and all(len(x)==2 for x in rows)
assert dict(sorted(Counter(str(x[0]) for x in rows).items()))==p["file_id_counts"]=={"1":1611,"2":2}
assert len(set(map(tuple,rows)))==1613 and rows[:6]==p["first_rows"] and rows[-6:]==p["last_rows"]
names=w["assembly_name_table"]["names"]
assert len(names)==13 and names[1]==""
assert names[2:4]==["Assembly-CSharp-firstpass.dll","Assembly-CSharp.dll"]
assert "uAudio.dll" in names and "Rewired_Core.dll" in names and "uCPf.dll" in names
assert w["assembly_name_table"]["count_offset"]==19360 and w["assembly_name_table"]["end_offset"]==19672
assert w["external_reference_join"]=={"1":"globalgamemanagers.assets","2":"library/unity default resources"}
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0334"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY MONOMANAGER ORIGINAL 1613 SCRIPT REFERENCES 13 ASSEMBLIES: PASS")
