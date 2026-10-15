"""FACT-0351 source-only indexed original 440 first-entry header and original DLL field map."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_first_entry_header_12_byte.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0351-original-fpw-first-entry-header-source-index.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
prior=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json').read_text())['dll']
o=w['observed'];d=w['original_dll'];p=w['original_panel']
assert f['fact_id']=='FACT-0351' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2
assert (o['source_objects'],o['unique_12_byte_headers'],o['sibling_families'],o['sibling_pairs'],o['sibling_pairs_matching_full_12_bytes'],o['sibling_pairs_differing_full_12_bytes'])==(440,305,65,79,75,4)
assert o['concatenated_440_12_byte_headers_sha256']=='c2cea392b5a818ceaa850d26be900d62cec321bcd571ceb58fe468ef76935fb3'
assert o['indexed_440_source_rows_sha256']=='93abc0c9dc1ff9c90490637d222b414615c4ec2c28951f51c098285389f2bf4c'
assert len(o['field_stats'])==12 and [x['offset'] for x in o['field_stats']]==list(range(64,76))
assert len(o['sibling_pairs_with_nonmatching_12_bytes'])==4
assert prior['sha256']==d['sha256'] and prior['method']['code_sha256']==d['full_il_sha256'] and prior['window']['source_sha256']==d['first_entry_window_il_sha256']
assert prior['window']['source_byte_offsets_read']==d['first_entry_read_offsets']
assert prior['window']['cursor_positions_skipped_without_read']==d['first_entry_cursor_skip_offsets']
assert {z['source']:z['name'] for z in prior['window']['fields'] if isinstance(z['source'],int)}=={z['source_offset']:z['name'] for z in d['original_field_labels']}
assert len([s for s in m['sources'] if s['source_id']=='RESPANEL-001' and s['sha256']==p['sha256']])==1
assert len([s for s in m['sources'] if s['source_id']=='DLL-001' and s['sha256']==d['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0351' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False and d['runtime_asset_loaded_proven'] is False
print('FACT-0351 original first-entry source field index summary PASS')
