"""FACT-0350 original 79 sibling source pair window index: static witness checks."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_sibling_byte_diff_windows.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0350-original-fpw-sibling-byte-difference-windows.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
o=w['observed']
assert f['fact_id']=='FACT-0350' and f['status']=='PROVEN_PACKED_DATA'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001'}
assert len(f['chain_edges'])==2
assert (o['source_objects'],o['sibling_families'],o['pairwise_comparisons'])==(440,65,79)
assert (o['pairs_0_1'],o['pairs_0_2'],o['pairs_1_2'])==(65,7,7)
assert (o['all_pairs_equal_source_length'],o['all_pairs_not_identical'],o['all_pairs_equal_offset48_63'])==(79,79,79)
assert o['pairs_with_changes']==[62,0,4,79]
assert o['total_changed_bytes_by_range']==[128,0,7,7836]
assert o['total_changed_bytes_all_pairs']==7971
assert (o['min_pair_changed_bytes'],o['max_pair_changed_bytes'])==(14,417)
assert (o['min_first_changed_index'],o['max_last_changed_index'])==(9,1283)
assert o['normalized_79_pair_rows_sha256']=='61ba2c2012dc91eeffe4a178ca0e4c2187a392f51c98d8cf9ce1aaf533364f81'
assert (w['original_panel']['bytes'],w['original_panel']['sha256'])==(330116,'0fdcac6e1b83c237de0b7f867cff3d61f7d97831efe08be9e4dcece346ba5b53')
assert w['original_panel']['report_sha256']=='034dada3887209542c37d9cf704345868661564b0e7a6b758f4b58e7a99c0cfc'
assert len([s for s in m['sources'] if s['source_id']=='RESPANEL-001' and s['sha256']==w['original_panel']['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0350' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked']
print('FACT-0350 original sibling source byte comparison summary PASS')
