"""FACT-0332: original ShaderNameRegistry compact complete-source witness gate."""
import base64,hashlib,json,zlib
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/shader_name_registry_206.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0332-original-unity-shader-name-registry.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert f["fact_id"]=="FACT-0332" and f["status"]=="PROVEN_PACKED_DATA"
assert w["object"]=={"class_id":94,"class_name":"ShaderNameRegistry","type_index":4,"path_id":5,"absolute_offset":37032,"relative_offset":32936,"bytes":9561,"sha256":"4cefc714845bde7c9e66a11fafea47d8eaecd4309d2b46b3b67628ca4ae42ab2"}
assert w["table"]["count"]==206 and w["table"]["rows_end_offset"]==9560
source=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert source["canonical_eligible"] and source["sha256"]==w["original_file"]["sha256"]
archive=w["rows_archive"]
data=zlib.decompress(base64.b64decode(archive["data"]))
assert len(data)==archive["decoded_bytes"]==8087
assert hashlib.sha256(data).hexdigest()==archive["decoded_sha256"]
rows=json.loads(data)
assert len(rows)==206
assert dict(sorted(Counter(str(r[0]) for r in rows).items()))==w["file_id_counts"]
fi=[dict(index=i,file_id=a,path_id=b,name=c) for i,(a,b,c) in enumerate(rows) if c.startswith("FiPro/")]
assert len(fi)==11
for x,y in zip(fi,w["fipro_names"]):
    assert all(x[k]==y[k] for k in x)
assert [x[:3] for x in rows[:3]]==[[1,14,"FiPro/CustomSprite"],[1,6,"FiPro/CustomSprite_Additive"],[1,7,"FiPro/CustomSprite_HighlightMap"]]
assert w["external_reference_join"]=={"1":"globalgamemanagers.assets","5":"resources.assets"}
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0332"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL SHADER NAME REGISTRY 206 FULL ROWS / 11 FIPRO: PASS")
