"""FACT-0333: Unity InputManager 437 original rows immutable summary and lock invariants."""
import base64,hashlib,json,zlib
from collections import Counter
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/input_manager_437_rows.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0333-original-unity-input-manager.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
manifest=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"],f["chain_edges"])==("FACT-0333","PROVEN_PACKED_DATA",[])
o=w["object"]
assert (o["class_id"],o["type_index"],o["path_id"],o["relative_offset"],o["absolute_offset"],o["bytes"])==(13,1,2,552,0x1228,31408)
src=next(s for s in manifest["sources"] if s["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
a=w["rows_archive"];b=zlib.decompress(base64.b64decode(a["data"]))
assert (len(b),hashlib.sha256(b).hexdigest())==(29436,"f49f111b7836067a9f0d642ba02e21888e4ffb5bd37782c8f3095b3991fd965f")
rows=json.loads(b)
assert len(rows)==w["table"]["count"]==437
assert all(len(row)==17 for row in rows)
assert len({x[0] for x in rows})==436
assert rows[0][0]=="Horizontal" and rows[8][0]=="Vertical"
assert rows[42][0]=="Submit" and rows[43][0]=="Submit" and rows[44][0]=="Cancel"
assert rows[42][4]=="return" and rows[42][6]=="joystick button 0"
assert rows[43][4]=="enter" and rows[43][6]=="space"
assert rows[44][4]=="escape" and rows[44][6]=="joystick button 1"
assert rows[436][0]=="MouseButton6" and rows[436][4]=="mouse 6"
assert sum(bool(v) for r in rows for v in r[:7])==w["counts"]["nonempty_string_slots"]==525
assert dict(sorted(Counter(str(r[-3]) for r in rows).items()))==w["counts"]["first_tail_code_counts"]=={"0":70,"1":6,"2":361}
assert dict(sorted(Counter(bytes(r[10:14]).hex() for r in rows).items()))==w["counts"]["four_byte_region_hex_counts"]
e=[x for x in reg["families"] if x["fact_id"]=="FACT-0333"]
assert len(e)==1 and e[0]["family_id"]==w["dataset_id"] and e[0]["runtime_eligible"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
assert reg["runtime_unlocked"] is False
print("UNITY ORIGINAL INPUT MANAGER 437 FULL SOURCE AXIS ROWS: PASS")
