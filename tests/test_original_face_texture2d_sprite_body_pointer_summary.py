"""FACT-0370 original face Texture2D/Sprite source-only binary link summary and regression."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/RESOBJECT-001/original_face_texture2d_sprite_body_pointer.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0370-original-face-texture2d-sprite-body-internal-pptr.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
prior=json.loads((R/'canonical/facts/FACT-0369-original-partstex-named-texture-sprite-object-joins.json').read_text())
fixed=(R/'tools/prove_original_partstex_named_object_joins.py').read_text()
assert f['fact_id']=='FACT-0370' and f['status']=='PROVEN_PACKED_DATA'
assert prior['fact_id']=='FACT-0369' and s['parent_fact']=='FACT-0369'
assert s['source_ids']==['GGM-001','RESMETA-001','RESOBJECT-001']
assert s['private_witness']['committed_to_git'] is False
assert [(x['path_id'],x['source_class_id'],x['byte_count']) for x in s['source_objects']]==[(15464,28,54592),(41553,213,8268)]
assert s['source_object_names']['resource_manager_row_indices']==[3861,3862]
assert s['sprite_observations']['internal_texture_pptr_i32_fileid_at80']==0
assert s['sprite_observations']['internal_texture_pptr_i64_pathid_at84']==15464
assert s['sprite_observations']['linked_original_texture_object_pathid']==15464
assert s['texture2d_observations']['width_i32_at20']==532 and s['texture2d_observations']['height_i32_at24']==700
assert s['prover_repair']['source_data_affected'] is False
assert "count=struct.unpack_from('<I',m,p)[0];p=(p+3)&~3\n    p+=4" in fixed
assert len([x for x in r['families'] if x['fact_id']=='FACT-0370' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0370 original face sprite internal texture link summary PASS')
