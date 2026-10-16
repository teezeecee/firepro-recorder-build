"""FACT-0372 original retail Texture2D CRN container summary-only regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/RESOBJECT-001/original_face_texture2d_crn_container.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0372-original-face-texture2d-crn-container.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
old=json.loads((R/'canonical/witnesses/RESOBJECT-001/original_face_texture2d_sprite_body_pointer.summary.json').read_text())
assert s['parent_fact']=='FACT-0371' and s['source_ids']==['RESOBJECT-001']
assert f['fact_id']=='FACT-0372' and f['status']=='PROVEN_PACKED_DATA'
assert s['source_texture']['sha256']==old['source_objects'][0]['sha256']
assert s['private_witness']['committed_to_public_git'] is False
assert s['private_witness']['repository']=='teezeecee/firepro-retail-evidence-vault'
u=s['unity_fields'];h=s['crn_header'];a=s['crn_regions']
assert (u['width'],u['height'],u['texture_format_numeric'],u['complete_image_size'])==(532,700,29,54497)
assert (h['header_size'],h['data_size'],h['width'],h['height'],h['levels'],h['faces'],h['crn_format'])==(74,54497,532,700,1,1,2)
assert a['color_endpoints']['offset']==74
seq=['color_endpoints','color_selectors','alpha_endpoints','alpha_selectors','tables','mip0']
assert all(a[seq[i]]['end']==a[seq[i+1]]['offset'] for i in range(len(seq)-1))
assert a['mip0']['end']==54497 and a['mip0']['size']==41790
assert sum(a[x]['size'] for x in seq)==54497-74
assert u['encoded_object_end_exclusive']==54577 and u['encoded_object_end_exclusive']+u['tail_zero_bytes']==54592
assert len([x for x in r['families'] if x['fact_id']=='FACT-0372' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0372 original DXT5Crunched container header and section summary PASS')
