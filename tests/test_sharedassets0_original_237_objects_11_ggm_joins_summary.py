"""FACT-0343 static source-only external original parent integrity."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'canonical/witnesses/SA0-001/original_237_objects_11_ggm_joins.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0343-original-sharedassets0-objectinfo-ggm-joins.json').read_text())
m=json.loads((ROOT/'canonical/source_manifest.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
assert f['fact_id']=='FACT-0343' and f['status']=='PROVEN_PACKED_DATA' and f['chain_edges']==[]
assert set(e['source_id'] for e in f['evidence'])=={'SA0-001','GGM-001'}
assert w['source_ids']==['SA0-001','GGM-001']
assert w['original_files']['sharedassets0']['sha256']=='a306d8b262b11820dd4f24801db3ca158ce0e446f1a2f667951d83d6ec513521'
assert w['original_files']['globalgamemanagers']['sha256']=='04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c'
assert (w['metadata']['type_count'],w['metadata']['object_count'])==(31,237)
assert (w['metadata']['objectinfo_start'],w['metadata']['objectinfo_end'])==(980,5720)
d=w['payload']; assert (d['objects'],d['object_body_bytes'],d['gap_count'],d['gap_bytes'])==(237,10534433,130,503)
assert d['bytes']==d['object_body_bytes']+d['gap_bytes']==10534936
assert d['empty_objects']==0 and d['all_gaps_zero'] is True
assert sum(d['class_id_counts'].values())==237
assert d['class_id_counts']['114']==182
assert sum(int(k)*v for k,v in d['gap_length_histogram'].items())==503
assert sum(d['gap_length_histogram'].values())==130
j=w['ggm_join'];assert j['original_external_file_id']==4 and j['original_file_id4_dependency_name']=='sharedassets0.assets'
assert j['named_fileid4_occurrences']==len(j['anchors'])==11 and j['all_path_ids_resolve'] is True
assert len(set(x['path_id'] for x in j['anchors']))==11
assert all(x['file_id']==4 and x['object_body_bytes']>0 and len(x['object_body_sha256'])==64 for x in j['anchors'])
assert next(x for x in m['sources'] if x['source_id']=='SA0-001')['sha256']==w['original_files']['sharedassets0']['sha256']
assert next(x for x in m['sources'] if x['source_id']=='GGM-001')['sha256']==w['original_files']['globalgamemanagers']['sha256']
assert len([x for x in r['families'] if x['fact_id']=='FACT-0343'])==1
assert next(x for x in r['families'] if x['fact_id']=='FACT-0343')['runtime_eligible'] is False
assert r['runtime_unlocked'] is False
print('FACT-0343 ORIGINAL SHAREDASSETS0 237 OBJECTS AND 11 GGM JOINS: PASS')
