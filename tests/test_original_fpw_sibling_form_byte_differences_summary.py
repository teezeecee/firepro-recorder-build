"""FACT-0354 source only 79 suffix sibling pairs and 3610 aligned original 12-byte form comparisons."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
w=json.loads((ROOT/'canonical/witnesses/RESPANEL-001/original_79_sibling_pairs_3610_form_byte_differences.summary.json').read_text())
f=json.loads((ROOT/'canonical/facts/FACT-0354-original-fpw-sibling-form-byte-difference-index.json').read_text())
m=json.loads((ROOT/'canonical/source_manifest.json').read_text())
r=json.loads((ROOT/'canonical/transition_registry.json').read_text())
o=w['observed'];p=w['original_panel'];d=w['original_dll']
assert f['fact_id']=='FACT-0354' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==2
assert (o['source_objects'],o['sibling_families'],o['sibling_pair_count'])==(440,65,79)
assert (o['two_member_families'],o['three_member_families'])==(58,7)
assert o['pair_suffix_counts']=={'0_1':65,'0_2':7,'1_2':7}
assert (o['aligned_form_pair_comparisons'],o['identical_aligned_form_pairs'],o['different_aligned_form_pairs'])==(3610,1186,2424)
assert o['all_sibling_pair_form_counts_aligned']==o['all_sibling_pair_vectors_equal']==o['all_sibling_pairs_have_at_least_one_different_form']==79
assert (o['sibling_pairs_with_same_first_12_byte_header'],o['sibling_pairs_with_different_first_12_byte_header'])==(75,4)
assert o['original_byte_offsets_with_form_pair_differences']==[483,1378,259,1688,1506,1515,10,581,12,364,2,38]
assert o['sibling_pairs_with_any_differences_in_each_form_byte_offset']==[44,79,44,79,78,78,2,41,5,42,1,16]
assert o['indexed_79_pair_summary_sha256']=='094a628a4fba8605641eb5d0730b8112aebf715a603400ea6437d745af9fc2d2'
assert o['indexed_3610_aligned_form_comparison_sha256']=='e0391e475eedb4da3a6199ea7267499d6d6c3f1c5bf8afbde986bde00e36b65a'
assert len(d['input_byte_to_source_label'])==12 and [s['offset'] for s in d['input_byte_to_source_label']]==list(range(12))
prior=json.loads((ROOT/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_offset_pos_and_disp_frame.summary.json').read_text())['dll']
assert prior['sha256']==d['sha256'] and prior['method']['code_sha256']==d['method_il_sha256']
assert any(s['offset']==6 and 'dispFrm' in s['label'] for s in d['input_byte_to_source_label'])
assert len([x for x in m['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==p['sha256']])==1
assert len([x for x in m['sources'] if x['source_id']=='DLL-001' and x['sha256']==d['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0354' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked'] and not d['direct_retail_runtime_asset_selection_proven']
print('FACT-0354 original 79 sibling pair form source diff summary PASS')
