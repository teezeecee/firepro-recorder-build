"""FACT-0322 BuildSettings API list original source witness structure regression."""
import hashlib
import json
import struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/"canonical/witnesses/GGM-001/buildsettings_graphics_apis.summary.json").read_text())
f=json.loads((ROOT/"canonical/facts/FACT-0322-globalgamemanagers-buildsettings-graphics-apis.json").read_text())
manifest=json.loads((ROOT/"canonical/source_manifest.json").read_text())
reg=json.loads((ROOT/"canonical/transition_registry.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0322","PROVEN_PACKED_DATA")
assert w["dataset_id"]=="UNITY_BUILDSETTINGS_GRAPHICS_APIS_ORDER_V1" and w["source_ids"]==["GGM-001"]
assert len(f["evidence"])==1 and f["evidence"][0]["source_id"]=="GGM-001"
s=next(x for x in manifest["sources"] if x["source_id"]=="GGM-001")
assert s["canonical_eligible"] is True and s["availability"]=="VERIFIED_LOCAL_BYTES"
assert (s["sha256"],s["size_bytes"])==(w["file"]["sha256"],5002540)
b=w["build_settings"];api=b["graphics_api_field"]
assert (b["class_id"],b["type_index"],b["path_id"])==(141,10,11)
assert (b["file_offset"],b["size_bytes"])==(67040,55660)
assert b["runtime_class_hashes"]=={"offset":3472,"count":154,"record_bytes":20}
assert b["script_hashes"]=={"offset":6556,"count":1534,"record_bytes":32}
assert 3472+4+154*20==6556
assert 6556+4+1534*32==api["offset"]
assert api["offset"]+4+4*api["count"]==b["size_bytes"]
assert api["absolute_offset"]==b["file_offset"]+api["offset"]
assert api["ordered_numeric_values"]==[2,1]
assert bytes.fromhex(api["field_hex"])==struct.pack("<III",2,2,1)
assert w["graphics_device_enum_source"]["numeric_map"]=={"1":"Direct3D9","2":"Direct3D11"}
match=[x for x in reg["families"] if x["fact_id"]=="FACT-0322"]
assert len(match)==1 and match[0]["family_id"]==w["dataset_id"]
assert match[0]["runtime_eligible"] is False
assert reg["runtime_unlocked"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("GLOBALGAMEMANAGERS BUILDSETTINGS API ORDER SOURCE SUMMARY: PASS")
