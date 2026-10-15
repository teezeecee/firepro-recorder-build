"""FACT-0355 original SHA-pinned 23,037 source form numeric input decode summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_23037_fpw_form_numeric_fields.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0355-original-fpw-form-numeric-field-decode.json').read_text())
s=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
o=w['observed'];dll=w['original_dll'];panel=w['original_panel']
assert f['fact_id']=='FACT-0355' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert set(q['source_id'] for q in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==3
assert (o['source_objects'],o['segment_header_blocks'],o['form_record_count'],o['form_source_bytes'])==(440,1347,23037,276444)
assert o['original_concatenated_23037_form_raw_bytes_sha256']=='93807a1a2d1208e693ef225d80598f3d1fb70f58d2a132d63fd052c97668ba18'
assert o['full_original_23037_decoded_numeric_rows_sha256']=='06c901a9d5f98eb37254b916a4916f077c1824b9bd833533ba064c50df6114bf'
assert o['distinct_packed_formIdx_values']==7214
assert o['numeric_field_distributions']['dispFrm']=={'distinct':43,'min':1,'max':90,'zero':0}
assert o['numeric_field_distributions']['formIdx']=={'distinct':7214,'min':100,'max':37998,'zero':0}
assert o['numeric_field_distributions']['effectID_initial']=={'distinct':1,'min':-1,'max':-1,'zero':0}
assert len(o['numeric_field_distributions'])==17
assert sum(x['source_bytes_advanced'] for x in dll['reader_windows'])==12
for item in dll['reader_windows']:
    prior=json.loads((R/'canonical/witnesses/CAP-R6-001'/item['witness']).read_text())['dll']
    assert prior['sha256']==dll['sha256'] and prior['method']['token']==dll['methoddef'] and prior['method']['code_sha256']==dll['method_il_sha256']
    assert (prior['window']['start_il'],prior['window']['end_exclusive_il'],prior['window']['source_sha256'])==(item['start_il'],item['end_exclusive_il'],item['il_sha256'])
assert len([x for x in s['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==panel['sha256']])==1
assert len([x for x in s['sources'] if x['source_id']=='DLL-001' and x['sha256']==dll['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0355' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked'] and not dll['specific_original_textasset_load_or_playback_proven']
print('FACT-0355 original 23037 decoded source numeric fields summary PASS')
