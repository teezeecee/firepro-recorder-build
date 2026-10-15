"""FACT-0357 complete 7214-value original formIdx source occurrence summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1];P=R/'canonical/witnesses/RESPANEL-001'
w=json.loads((P/'original_23037_fpw_formidx_occurrence_index.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0357-original-fpw-formidx-source-occurrence-index.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
s=json.loads((R/'canonical/source_manifest.json').read_text())
p=json.loads((P/'original_23037_fpw_form_numeric_fields.summary.json').read_text())
o=w['observed']
assert f['fact_id']=='FACT-0357' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert {x['source_id'] for x in f['evidence']}==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==4
assert (o['source_objects'],o['source_form_records'],o['distinct_formIdx_values'])==(440,23037,7214)
assert (o['formIdx_min'],o['formIdx_max'])==(100,37998)
assert (o['single_occurrence_values'],o['multiple_occurrence_values'],o['occurrences_of_repeated_values'])==(3852,3362,19185)
assert (o['multiple_source_object_values'],o['occurrences_of_multiple_source_object_values'],o['one_source_object_values'])==(2348,16012,4866)
assert (o['max_occurrence_value'],o['max_occurrences'],o['max_distinct_source_objects'])==(100,858,294)
assert o['complete_7214_value_occurrence_index_sha256']=='b9926f62a5eb559ca608d8b52697ca75a4f83cfe718adc492dce504aba0b6cda'
assert o['frequency_histogram_sha256']=='c57c3a2a242f302ccdacc442a62441c35f683c1d8c5ebf051c0488588d930f79'
assert o['prior_23037_numeric_source_rows_sha256']==p['observed']['full_original_23037_decoded_numeric_rows_sha256']
assert [a['formIdx'] for a in w['anchors']]==[100,101,4372,37998]
assert w['anchors'][0]['occurrences']==858 and w['anchors'][0]['distinct_source_objects']==294
assert w['anchors'][1]['occurrences']==486 and w['anchors'][1]['distinct_source_objects']==182
assert len([x for x in s['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==w['original_panel']['sha256']])==1
assert len([x for x in s['sources'] if x['source_id']=='DLL-001' and x['sha256']==w['original_dll']['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0357' and x['runtime_eligible'] is False])==1 and not r['runtime_unlocked']
print('FACT-0357 original formIdx complete occurrence source summary PASS')
