"""FACT-0346 original retail object summary: source-only static guard."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESOBJ-002/fpw_6172_exact_1716_byte_object.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0346-original-fpw6172-1716-byte-resource-object.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
o=w['object_source'];a=w['metadata_source'];z=w['ggm_source'];p=w['payload']
assert f['fact_id']=='FACT-0346' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESOBJ-002','RESMETA-001','GGM-001'}
assert w['dataset_id']=='UNITY_RESOURCES_FPW6172_SINGLE_OBJECT_ORIGINAL_BYTES_V1'
assert (o['size_bytes'],o['sha256'])==(1716,'de13a6efdff9727d63542134096b056f2c680c606b7703e82b4fd6839fc30cf1')
assert (o['original_absolute_offset'],o['original_end_exclusive'])==(1957193440,1957195156)
assert o['original_full_file_rehashed'] is False and o['original_prior_export_sha256']==o['sha256']
assert a['sha256']=='8388d7e2401172e5ee1139f617afeac8a68aaeb64383bc076098a922e45151da'
assert (a['row_offset'],a['row_sha256'])==(444252,'6f6e7f8c1b77b01b73ceced82e68bc28f9467f3201a24fb01b639b2435f43a52')
assert (a['data_offset'],a['path_id'],a['type_index'],a['class_id'],a['relative_offset'],a['object_bytes'])==(1842224,21353,4,49,1955351216,1716)
assert z['sha256']=='04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c'
assert (z['name_index'],z['name'],z['file_id'],z['path_id'])==(43890,'wrestleranimation/fpw_6172',5,21353)
assert (p['name_len'],p['name'],p['embedded_len'],p['embedded_sha256'])==(8,'fpw_6172',1696,'efd723b5f26a6719d2d3d1706289c82720be9364603609661c3b198a0a59064c')
assert p['embedded_prefix_hex']=='5253' and p['trailer_hex']=='00000000' and p['bytes_accounted']==1716
assert w['comparison_prior']['fact']=='FACT-0345'
assert len([s for s in m['sources'] if s['source_id']=='RESOBJ-002' and s['sha256']==o['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0346' and not x['runtime_eligible']])==1
assert r['runtime_unlocked'] is False
print('FACT-0346 original fpw_6172 source exact record: PASS')
