"""FACT-0366 source summary and canonical relationship checks."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'canonical/witnesses/DLL-001/original_formrenderer_part_source_consumers.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0366-original-formrenderer-texture-part-offset-consumers.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
prev=json.loads((ROOT/'canonical/witnesses/DLL-001/original_rff_gettexcellidx_direct_callers_partsnum.summary.json').read_text())
assert f['fact_id']=='FACT-0366' and f['status']=='PROVEN_DLL'
assert {a['source_id'] for a in f['evidence']}==set(w['source_ids'])=={'DLL-001'}
assert len(f['chain_edges'])==1 and w['private_witness']['committed_to_git'] is False
assert w['original_dll']['sha256']==prev['original_dll']['sha256']
assert [x['name'] for x in w['source_method_bodies']]==['SetPartsObj','CalcPartsOffset','TexKind2PartsKind']
assert [x['il_length'] for x in w['source_method_bodies']]==[1710,196,281]
assert all(x['owner']=='FormRenderer' and len(x['il_sha256'])==64 for x in w['source_method_bodies'])
assert len(w['source_windows'])==7 and all(len(x['sha256'])==64 and x['start']<x['end'] for x in w['source_windows'])
assert w['source_instructions']['setpartsobj']['calc_offset_method_call_opcode_offset']==155
assert w['source_instructions']['texkind2partskind']['switch_target_count']==9
assert [x['token'] for x in w['original_fields']][:2]==['0x040026C0','0x040026C1']
assert len([x for x in r['families'] if x['fact_id']=='FACT-0366' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0366 original FormRenderer texKind/cellIdx direct source consumer PASS')
