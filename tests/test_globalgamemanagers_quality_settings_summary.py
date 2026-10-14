"""FACT-0323 original source QualitySettings exact full 116-byte witness regression."""
import hashlib
import json
import struct
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/"canonical/witnesses/GGM-001/quality_settings_fantastic.summary.json").read_text())
f=json.loads((R/"canonical/facts/FACT-0323-globalgamemanagers-quality-settings-fantastic.json").read_text())
reg=json.loads((R/"canonical/transition_registry.json").read_text())
m=json.loads((R/"canonical/source_manifest.json").read_text())
assert (f["fact_id"],f["status"])==("FACT-0323","PROVEN_PACKED_DATA")
assert w["dataset_id"]=="UNITY_QUALITYSETTINGS_SINGLE_FANTASTIC_PROFILE_V1" and w["source_ids"]==["GGM-001"]
src=next(s for s in m["sources"] if s["source_id"]=="GGM-001")
assert src["canonical_eligible"] and src["sha256"]==w["original_file"]["sha256"]
q=w["quality_settings"];raw=bytes.fromhex(q["full_body_hex"])
assert len(raw)==116 and hashlib.sha256(raw).hexdigest()==q["sha256"]
assert (q["class_id"],q["type_index"],q["path_id"])==(47,11,12)
assert (q["absolute_offset"],q["size_bytes"])==(0x1DF50,116)
assert struct.unpack_from("<iii",raw,0)==(0,1,9) and raw[12:21]==b"Fantastic"
fields=q["fields"]
assert [fields[v] for v in ("m_CurrentQuality","m_QualitySettings_count","pixelLightCount","shadows","shadowResolution","shadowCascades","textureQuality","anisotropicTextures","antiAliasing","vSyncCount","particleRaycastBudget")]==[0,1,4,2,2,4,0,2,2,0,4096]
assert struct.unpack_from("<i",raw,0x50)[0]==2 and struct.unpack_from("<i",raw,0x58)[0]==0
found=[x for x in reg["families"] if x["fact_id"]=="FACT-0323"]
assert len(found)==1 and found[0]["family_id"]==w["dataset_id"]
assert found[0]["runtime_eligible"] is False and reg["runtime_unlocked"] is False
assert len({x["family_id"] for x in reg["families"]})==len(reg["families"])
print("GLOBALGAMEMANAGERS QUALITY SETTINGS SUMMARY: PASS")
