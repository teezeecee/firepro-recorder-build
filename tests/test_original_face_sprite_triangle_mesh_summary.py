"""FACT-0371 source-only original Sprite index and vertex SHA summary regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/RESOBJECT-001/original_face_sprite_triangle_mesh_source.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0371-original-face-sprite-index-and-vertex-buffer.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
p=json.loads((R/'canonical/witnesses/RESOBJECT-001/original_face_texture2d_sprite_body_pointer.summary.json').read_text())
assert (f['fact_id'],f['status'])==('FACT-0371','PROVEN_PACKED_DATA')
assert s['source_ids']==['RESOBJECT-001'] and s['parent_fact']=='FACT-0370'
assert len(f['evidence'])==1 and f['evidence'][0]['source_id']=='RESOBJECT-001'
assert s['source_sprite']['sha256']==p['source_objects'][1]['sha256']
assert s['source_texture']['sha256']==p['source_objects'][0]['sha256']
assert s['private_witness']['committed_to_git'] is False
g=s['geometry'];w=s['regions']
assert (g['index_count'],g['triangle_count'],g['vertex_count'])==(735,245,327)
assert (g['minimum_index'],g['maximum_index'],g['unique_index_count'])==(0,326,327)
assert g['signed_xy_cross_signs']=={'negative':245,'positive':0,'zero':0}
assert (w['index_byte_count'],w['vertex_byte_count'],w['tail_byte_count'])==(1470,6540,52)
assert w['index_buffer_end']-w['index_buffer_start']==1470
assert w['vertex_buffer_end']-w['vertex_buffer_start']==327*20
assert w['tail_end']==8268
assert g['trailing_three_float32_components_all_zero'] is True
assert len([x for x in r['families'] if x['fact_id']=='FACT-0371' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0371 original Sprite 327 vertices/245 triangles source summary PASS')
