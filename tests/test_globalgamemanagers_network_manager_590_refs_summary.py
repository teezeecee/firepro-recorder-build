"""FACT-0340 static source-only witness checks (no retail file needed by CI)."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/GGM-001/network_manager_590_refs.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0340-original-unity-network-manager-590-references.json').read_text())
o=w['object'];t=w['record_table']
assert f['fact_id']=='FACT-0340' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert (o['class_id'],o['type_index'],o['path_id'])==(149,13,14)
assert (o['relative_offset'],o['absolute_offset'],o['bytes'])==(4981056,0x4C1140,16532)
assert o['sha256']=='f4fe8dc74035736ffd35c907e01ef11d46635cec7fb0924aa4f1785b6acc8133'
assert t['header_u32_words']==[0,0x41700000,590] and t['f32_at_object_offset_4_representation']==15
assert t['record_count']==590 and t['record_bytes_each']==28
assert t['records_start']==12 and t['records_end']==12+590*28==16532
assert t['header_sha256']=='6525204815fe05e8b2d170df1b12f9a06ccc47093371ae73674734c0ac98d207'
assert t['records_sha256']=='183eef19bceef1b0279a7457d8a6e7f57e48d889e164bd43d4cd6b77e2a58d75'
assert sum(t['fileid_counts'].values())==590 and t['fileid_counts']=={'4':6,'5':557,'7':9,'9':12,'10':1,'11':5}
assert t['unique_identifiers']==t['unique_numeric_references']==590
assert t['joined_fact0338_named_references']==534 and t['unmatched_named_index_references']==56
assert sum(t['matched_categories'].values())==534 and t['matched_categories']['interface']==437 and t['matched_categories']['stage']==90
assert sum(t['unmatched_fileid_counts'].values())==56
assert len(t['anchors'])==10 and t['anchors'][0]['index']==0 and t['anchors'][-1]['index']==589
assert w['outside_object_following_padding']=={'offset_absolute':o['end_absolute_offset'],'length':4,'hex':'00000000'}
reg_file=R/'canonical/transition_registry.json'
if reg_file.exists():
    reg=json.loads(reg_file.read_text())
    matches=[x for x in reg['families'] if x['fact_id']=='FACT-0340']
    assert len(matches)==1 and matches[0]['family_id']==w['dataset_id'] and matches[0]['runtime_eligible'] is False
    assert reg['runtime_unlocked'] is False
source_manifest=R/'canonical/source_manifest.json'
if source_manifest.exists():
    man=json.loads(source_manifest.read_text())
    src=next(x for x in man['sources'] if x['source_id']=='GGM-001')
    assert src['canonical_eligible'] and src['sha256']==w['original_file']['sha256']
print('FACT-0340 590-reference source-only static witness PASS')
