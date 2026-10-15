"""FACT-0344 original metadata-only source summary/static consistency."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESMETA-001/original_90992_objectinfo_43930_ggm_joins.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0344-original-resources-metadata-ggm-reference-joins.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
assert f['fact_id']=='FACT-0344' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert set(e['source_id'] for e in f['evidence'])=={'GGM-001','RESMETA-001'}
assert w['dataset_id']=='UNITY_RESOURCES_METADATA_90992_OBJECTINFO_43930_GGM_LINKS_V1'
p=w['metadata_prefix'];o=w['objectinfo'];t=w['types'];sr=w['script_refs'];e=w['externals'];j=w['ggm_join']
assert p['bytes']==1842222 and p['sha256']=='8388d7e2401172e5ee1139f617afeac8a68aaeb64383bc076098a922e45151da'
assert p['original_file_bytes_declared']==3166587532 and p['whole_file_bytes_available'] is False
assert p['full_file_sha256_rechecked_for_prefix_probe'] is False
assert p['metadata_prefix_excludes_data_offset_gap_bytes']==2
assert t['count']==455 and t['unique_class_ids']==37 and t['class_id114_type_entries']==419
assert sum(t['class_id_type_record_counts'].values())==455
assert o['count']==o['unique_path_ids']==90992 and o['nonzero_sizes']==90992
assert o['table_start']==17212 and o['table_end']==1837052
assert o['declared_payload_bytes']==o['declared_body_bytes_sum']+o['declared_gap_bytes_sum']==3164745308
assert o['declared_gap_windows_sum']==64064 and o['declared_gap_bytes_sum']==239756
assert sum(o['class_id_object_counts'].values())==90992
assert sum(o['declared_gap_length_counts'].values())==64064
assert sum(int(k)*v for k,v in o['declared_gap_length_counts'].items())==239756
assert sr['count']==414 and sr['unique_pairs']==414 and sr['file_id_counts']=={'1':414}
assert e['count']==len(e['entries'])==4 and e['entries'][1]['path']=='sharedassets0.assets'
assert e['entries'][0]['path']=='globalgamemanagers.assets'
assert j['ggm_file_id']==5 and j['ggm_external_target_name']=='resources.assets'
assert j['named_reference_count']==j['unique_target_path_ids']==j['resolved_in_metadata_count']==43930
assert j['unresolved_count']==0 and len(j['anchors'])==11
assert sum(j['reference_category_counts'].values())==43930
assert sum(j['target_class_id_counts'].values())==43930
assert len(set(a['path_id'] for a in j['anchors']))==11
assert all(a['file_id']==5 and len(a['objectinfo_row_sha256'])==64 for a in j['anchors'])
assert next(s for s in m['sources'] if s['source_id']=='RESMETA-001')['sha256']==p['sha256']
assert next(s for s in m['sources'] if s['source_id']=='GGM-001')['sha256']==w['original_ggm']['sha256']
assert len([x for x in r['families'] if x['fact_id']=='FACT-0344'])==1
assert next(x for x in r['families'] if x['fact_id']=='FACT-0344')['runtime_eligible'] is False
assert r['runtime_unlocked'] is False
print('FACT-0344 SOURCE-ONLY 90992 ObjectInfo, 43930 GGM numeric joins: PASS')
