"""FACT-0369 source-only original GGM / resources metadata named object joins."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/RESMETA-001/original_partstex_named_texture_sprite_object_joins.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0369-original-partstex-named-texture-sprite-object-joins.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
prev=json.loads((R/'canonical/facts/FACT-0344-original-resources-metadata-ggm-reference-joins.json').read_text())
assert f['fact_id']=='FACT-0369' and f['status']=='PROVEN_PACKED_DATA'
assert s['source_ids']==['GGM-001','RESMETA-001']
assert {a['source_id'] for a in f['evidence']}==set(s['source_ids'])
assert prev['fact_id']=='FACT-0344' and s['previous_object_table_fact']=='FACT-0344'
assert s['private_witness']['committed_to_git'] is False
p=s['partstex'];assert (p['source_named_references'],p['distinct_names'],p['texture2d_refs'],p['sprite_refs'],p['dual_class_names'],p['texture2d_only_names'])==(35365,17686,17686,17679,17679,7)
assert sum(f['texture2d_count'] for f in p['folder_counts'])==17686
assert sum(f['sprite_count'] for f in p['folder_counts'])==17679
assert len(p['folder_counts'])==11 and len(p['texture2d_only_exact_names'])==7
assert all(n.startswith('partstex/p2_body/m_bo_5000_f_') for n in p['texture2d_only_exact_names'])
assert len([x for x in r['families'] if x['fact_id']=='FACT-0369' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0369 original named texture/sprite metadata join summary PASS')
