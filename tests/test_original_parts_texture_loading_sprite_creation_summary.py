"""FACT-0367 canonical source summary cross-check (no original proprietary bytes)."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/DLL-001/original_parts_texture_loading_sprite_creation.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0367-original-partstex-resource-and-sprite-creation-route.json').read_text())
reg=json.loads((R/'canonical/transition_registry.json').read_text())
prior=json.loads((R/'canonical/witnesses/DLL-001/original_formrenderer_part_source_consumers.summary.json').read_text())
assert f['fact_id']=='FACT-0367' and f['status']=='PROVEN_DLL'
assert w['source_ids']==['DLL-001'] and {a['source_id'] for a in f['evidence']}=={'DLL-001'}
assert len(f['chain_edges'])==1 and w['private_witness']['committed_to_git'] is False
assert w['original_dll']['sha256']==prior['original_dll']['sha256']
assert len(w['source_methods'])==6 and len(w['source_windows'])==7
assert [x['il_length'] for x in w['source_methods']]==[42,28,147,40,170,481]
assert all(len(x['il_sha256'])==64 for x in w['source_methods'])
assert [x['value'] for x in w['original_user_strings']]==['PartsTex/','/','_h','.png']
assert [(x['owner'],x['name']) for x in w['original_member_refs']]==[('UnityEngine.Resources','Load'),('UnityEngine.Sprite','Create'),('UnityEngine.SpriteRenderer','set_sprite')]
assert w['original_instruction_sites']['init_sprite']['sprite_create_offset']==422
assert w['original_instruction_sites']['init_sprite']['sprite_renderer_set_offset']==427
assert len([a for a in reg['families'] if a['fact_id']=='FACT-0367' and a['runtime_eligible'] is False])==1
assert reg['runtime_unlocked'] is False
print('FACT-0367 original texture loader and sprite source summary PASS')
