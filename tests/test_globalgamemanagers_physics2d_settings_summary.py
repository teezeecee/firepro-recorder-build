"""FACT-0330: original Unity Physics2DSettings serialized bytes static invariants."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/physics2d_settings_208_bytes.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0330-original-unity-physics2d-settings.json").read_text())
r=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0330","PROVEN_PACKED_DATA")
src=next(x for x in m["sources"] if x["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
o=w["object"]
assert (o["class_id"],o["class_name"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(19,"Physics2DSettings",16,17,4997952,0x4C5340,208)
g=w["gravity_2d"]
assert (g["offset"],g["bytes"],g["components_f32_approx"],g["words_hex"])==(0,8,[0,-9.81],["00000000","c3f51cc1"])
cfg=w["remaining_settings"]
assert (cfg["offset"],cfg["bytes"],cfg["source_u32_at_offset_76"])==(8,72,32)
assert len(cfg["exact_hex"])==144 and cfg["exact_hex"][-8:]=="20000000"
matrix=w["layer_collision_matrix"]
assert (matrix["offset"],matrix["bytes"],matrix["entry_count"],matrix["entry_width"],matrix["all_mask_words_unsigned"])==(80,128,32,4,4294967295)
assert len(matrix["entries"])==32
assert all((x["index"],x["offset"],x["hex"],x["unsigned_le"])==(i,80+i*4,"ffffffff",4294967295) for i,x in enumerate(matrix["entries"]))
assert all(len(x)==64 for x in (o["sha256"],g["region_sha256"],cfg["sha256"],matrix["exact_sha256"]))
assert 8+72+128==208
entries=[x for x in r["families"] if x["fact_id"]=="FACT-0330"]
assert len(entries)==1 and entries[0]["family_id"]==w["dataset_id"] and entries[0]["runtime_eligible"] is False
assert r["runtime_unlocked"] is False and len({x["family_id"] for x in r["families"]})==len(r["families"])
print("UNITY ORIGINAL PHYSICS2DSETTINGS 208 BYTE SOURCE: PASS")
