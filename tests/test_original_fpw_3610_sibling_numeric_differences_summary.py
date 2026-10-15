"""FACT-0356 SHA-pinned original 3610 suffix-sibling form numeric source differences."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1];base=R/'canonical/witnesses/RESPANEL-001'
w=json.loads((base/'original_3610_sibling_numeric_source_differences.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0356-original-sibling-numeric-source-differences.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
s=json.loads((R/'canonical/source_manifest.json').read_text())
b=json.loads((base/'original_79_sibling_pairs_3610_form_byte_differences.summary.json').read_text())
n=json.loads((base/'original_23037_fpw_form_numeric_fields.summary.json').read_text())
o=w['observed'];p=w['original_panel'];dll=w['original_dll']
assert f['fact_id']=='FACT-0356' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(e['source_id'] for e in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==3
assert (o['source_objects'],o['sibling_families'],o['sibling_pair_count'],o['aligned_form_comparisons'])==(440,65,79,3610)
assert (o['same_numeric_forms'],o['different_numeric_forms'],o['total_numeric_field_changes'])==(1186,2424,7681)
assert o['full_3610_numeric_change_index_sha256']=='2b5a11a77149e6b0c19f004166ab367de41fca341661665f38f3ee9dbc3380da'
assert o['parent_raw_comparison_rows_sha256']==b['observed']['indexed_3610_aligned_form_comparison_sha256']
assert o['parent_all_23037_numeric_rows_sha256']==n['observed']['full_original_23037_decoded_numeric_rows_sha256']
assert len(o['numeric_fields_changed_form_counts'])==len(o['numeric_fields_changed_pair_incidence'])==17
assert sum(o['numeric_fields_changed_form_counts'].values())==7681
assert o['numeric_fields_changed_form_counts']['dispFrm']==10
assert o['numeric_fields_changed_pair_incidence']['dispFrm']==2
assert o['numeric_fields_changed_form_counts']['effectID_initial']==0
assert o['numeric_fields_changed_pair_incidence']['effectID_initial']==0
assert [x['family'] for x in w['anchors']]==['fpw_2004','fpw_6048','fpw_6161']
assert len([x for x in s['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==p['sha256']])==1
assert len([x for x in s['sources'] if x['source_id']=='DLL-001' and x['sha256']==dll['sha256']])==1
assert dll['method_il_sha256']==n['original_dll']['method_il_sha256']
assert len([x for x in r['families'] if x['fact_id']=='FACT-0356' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked']
print('FACT-0356 complete original 3610 sibling numeric source comparison summary PASS')
