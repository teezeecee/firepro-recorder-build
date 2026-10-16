"""FACT-0364 source-only summary validation; never imports original values."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/DLL-001/original_rff_fieldrva_int32_tables.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0364-original-rff-embedded-fieldrva-lookup-values.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
assert f['fact_id']=='FACT-0364' and f['status']=='PROVEN_DLL'
assert w['source_ids']==['DLL-001'] and {e['source_id'] for e in f['evidence']}=={'DLL-001'}
a=w['embedded_sources']; m=w['nine_destination_arrays']
assert len(a)==8 and len(m)==9 and len(f['chain_edges'])==1
assert [x['element_count'] for x in a]==[42,51,50,44,48,74,95,118]
assert [x['element_count'] for x in m]==[42,51,50,51,44,48,74,95,118]
assert sum(x['element_count'] for x in a)==522 and sum(x['element_count'] for x in m)==573
assert [x['fieldrva_row'] for x in a]==list(range(175,183))
assert all(x['byte_count']==x['element_count']*4 and len(x['sha256'])==64 for x in a)
assert [x['source_field_token'] for x in a]==[f'0x{0x0400B7AA+i:08X}' for i in range(8)]
assert m[1]['source_field_token']==m[3]['source_field_token']
assert w['metadata']['member_ref_name']=='InitializeArray' and w['metadata']['int32_typeref_name']=='System.Int32'
assert w['private_source_report']['committed_to_repository'] is False
assert len([x for x in r['families'] if x['fact_id']=='FACT-0364' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
print('FACT-0364 original fieldrva SHA verified source summary PASS')
