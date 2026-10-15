"""FACT-0353 original full 23037 twelve-byte source form index summary and matching DLL reader order."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_23037_form_source_blocks.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0353-original-fpw-23037-form-source-block-index.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
o=w['observed'];d=w['original_dll'];p=w['original_panel']
assert f['fact_id']=='FACT-0353' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==3
assert (o['source_objects'],o['source_segments'],o['total_twelve_byte_source_blocks'],o['source_form_records'],o['source_form_bytes'])==(440,1347,24384,23037,276444)
assert o['distinct_form_record_raw_12_byte_patterns']==15571
assert (o['distinct_two_byte_big_endian_source_values_at_form_relative_2_3'],o['minimum_two_byte_big_endian_source_value_at_form_relative_2_3'],o['maximum_two_byte_big_endian_source_value_at_form_relative_2_3'])==(7214,100,37998)
assert o['concat_original_form_source_bytes_sha256']=='93807a1a2d1208e693ef225d80598f3d1fb70f58d2a132d63fd052c97668ba18'
assert o['normalized_440_source_rows_sha256']=='74e5ed2b12e07ba33463f7ec11e743889ce5e91afe967094b8940751cdbb79c9'
assert o['normalized_23037_form_rows_sha256']=='23b2891ea046ae01b8187044c19a86da9efbc0e24e9ec33ec25a4e3ac36f0f91'
assert len(o['form_record_byte_column_stats'])==12 and [x['byte_offset'] for x in o['form_record_byte_column_stats']]==list(range(12))
assert sum(x['bytes_consumed'] for x in d['form_reader_windows'])==d['source_layout_reader_input_bytes_per_form']==12
assert [j for x in d['form_reader_windows'] for j in x['bytes']]==list(range(12))
for spec in d['form_reader_windows']:
    witness=json.loads((R/'canonical/witnesses/CAP-R6-001'/spec['dll_witness']).read_text())['dll']
    assert witness['sha256']==d['sha256'] and witness['method']['token']==d['methoddef'] and witness['method']['code_sha256']==d['method_il_sha256']
    assert (witness['window']['start_il'],witness['window']['end_exclusive_il'],witness['window']['source_sha256'])==(spec['il_start'],spec['il_end'],spec['il_sha256'])
assert len([s for s in m['sources'] if s['source_id']=='RESPANEL-001' and s['sha256']==p['sha256']])==1
assert len([s for s in m['sources'] if s['source_id']=='DLL-001' and s['sha256']==d['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0353' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked'] and not d['specific_440_resource_executions_proven']
print('FACT-0353 exact 23037 original form source records and DLL input window PASS')
