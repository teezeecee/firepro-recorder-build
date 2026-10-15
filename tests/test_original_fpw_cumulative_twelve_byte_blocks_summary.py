"""FACT-0352 original 440 resources cumulative 12-byte source boundaries summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_cumulative_twelve_byte_blocks.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0352-original-fpw-cumulative-twelve-byte-source-blocks.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
d=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json').read_text())['dll']
o=w['observed'];p=w['original_panel'];dll=w['original_dll']
assert f['fact_id']=='FACT-0352' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2
assert (o['source_objects'],o['all_source_lengths_minus_64_multiple_of_12'],o['total_12_byte_blocks'],o['total_source_segments'],o['zero_step_plateau_positions'])==(440,440,24384,1347,5693)
assert (o['all_final_vectors_equal_total_blocks'],o['all_positive_cumulative_steps_equal_one_plus_segment_source_header_byte'])==(440,1347)
assert o['sum_source_header_first_byte_values']==23037
assert o['number_of_nonempty_slots_by_source']=={'1':55,'2':231,'3':64,'4':15,'5':4,'6':10,'7':12,'8':36,'9':4,'10':9}
assert o['normalized_440_source_segment_rows_sha256']=='c279e823a914f4221fb3d0124db6b924bc4733da1c81f3a6684e7c44cb92edfa'
assert o['normalized_1347_segment_rows_sha256']=='6b5ad7b0a954a5e304ed9493a257c0caeecd91c20efe60b6d83bd9b210bede49'
assert d['sha256']==dll['sha256'] and d['method']['code_sha256']==dll['full_il_sha256'] and d['window']['source_sha256']==dll['first_entry_il_sha256']
assert any(z.get('source')==64 and z['name']=='formNum' for z in d['window']['fields'])
assert len([s for s in m['sources'] if s['source_id']=='RESPANEL-001' and s['sha256']==p['sha256']])==1
assert len([s for s in m['sources'] if s['source_id']=='DLL-001' and s['sha256']==dll['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0352' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0352 original cumulative 12-byte source block index PASS')
