"""FACT-0347 canonical original 440-object panel; source-only static gate."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_rs_panel.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0347-original-440-fpw-rs-panel.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
p=w['original_packed'];q=w['original_companion'];a=w['original_metadata'];g=w['original_ggm'];o=w['observations']
assert f['fact_id']=='FACT-0347' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert w['dataset_id']=='UNITY_ORIGINAL_NAMED_FPW_RS_440_OBJECT_PANEL_V1'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','RESMETA-001','GGM-001'}
assert (p['bytes'],p['sha256'])==(330116,'0fdcac6e1b83c237de0b7f867cff3d61f7d97831efe08be9e4dcece346ba5b53')
assert p['full_parent_rehashed_in_probe'] is False and p['raw_original_bytes_in_git'] is False
assert (q['bytes'],q['sha256'])==(473482,'034dada3887209542c37d9cf704345868661564b0e7a6b758f4b58e7a99c0cfc')
assert (q['normalized_440_index_sha256'])=='94e49cfdbdb81c7501bdb7e1b00a9a4634f0804968ddee4689367e6387dea4ed'
assert len(q['normalized_440_index_fields'])==13
assert (a['bytes'],a['sha256'],a['type_index'],a['class_id'])==(1842222,'8388d7e2401172e5ee1139f617afeac8a68aaeb64383bc076098a922e45151da',4,49)
assert (g['bytes'],g['sha256'],g['source_file_id'])==(5002540,'04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c',5)
assert (g['selected_first_index'],g['selected_last_index'],g['selected_prefix'])==(43501,43940,'wrestleranimation/fpw_')
assert (o['source_object_count'],o['total_body_bytes'],o['embedded_total_bytes'])==(440,330116,320768)
assert (o['unique_whole_body_shas'],o['unique_embedded_payload_shas'],o['duplicate_embedded_pairs'])==(440,431,9)
assert (o['min_body_bytes'],o['max_body_bytes'])==(168,2508)
assert (o['name_length_count'],o['embedded_byte_offset_count'])==({'8':303,'10':137},{'16':303,'20':137})
assert o['embedded_concatenated_sha256']=='8ca3b661d6d27673fa9835389e0b6927950dfe04e4e0d131e8f5e864fdfc3374'
assert o['all_embedded_rs_prefix'] is True and o['all_embedded_internal_u32_at_prefix_plus_two_matches_embedded_size'] is True
assert len(w['anchors'])==3 and [x['path_id'] for x in w['anchors']]==[22222,21353,21624]
assert len([x for x in m['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==p['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0347' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0347 canonical source-only 440 fpw RS objects: PASS')
