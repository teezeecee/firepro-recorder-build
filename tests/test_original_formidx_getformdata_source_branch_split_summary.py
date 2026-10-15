"""FACT-0358 original GetFormData source IL and 23037 original formIdx branch group summary."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
W=R/'canonical/witnesses/RESPANEL-001/original_23037_formidx_getformdata_branch_source_split.summary.json'
w=json.loads(W.read_text());f=json.loads((R/'canonical/facts/FACT-0358-original-getformdata-formidx-source-branch-split.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
parent=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_form_data_lookup_and_parts_transfer.summary.json').read_text())
prev=json.loads((R/'canonical/witnesses/RESPANEL-001/original_23037_fpw_formidx_occurrence_index.summary.json').read_text())
a=w['observed'];d=w['original_dll'];p=w['original_panel']
assert f['fact_id']=='FACT-0358' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert {x['source_id'] for x in f['evidence']}==set(w['source_ids'])=={'DLL-001','RESPANEL-001'}
assert len(f['chain_edges'])==2 and len(w['anchors'])==4 and len(d['source_windows'])==5
assert d['methoddef']==parent['dll']['window']['methoddef']['token']=='0x06001F17'
assert d['rva']==parent['dll']['window']['methoddef']['rva']=='0x0010A4D0'
assert d['method_row_hex']==parent['dll']['window']['methoddef']['row_hex']
assert d['method_signature_hex']==parent['dll']['window']['methoddef']['signature_hex']
assert d['sha256']==parent['dll']['sha256'] and d['sha256']==prev['original_dll']['sha256']
assert d['code_bytes']==84 and d['code_sha256']=='68502418fd273429f220e8ad06717123d67e39fb6b67d5e698f11a159547270f'
assert d['branch_constants']=={'range_start':37000,'range_end_inclusive':37999}
assert (a['original_resource_objects'],a['total_original_form_records'],a['source_segment_headers'])==(440,23037,1347)
assert (a['regular_records'],a['block_range_records'])==(19010,4027)
assert (a['regular_distinct_formIdx_inputs'],a['block_distinct_formIdx_inputs'])==(6215,999)
assert (a['regular_source_objects'],a['block_source_objects'])==(404,179)
assert (a['regular_min'],a['regular_max'],a['block_min'],a['block_max'])==(100,36999,37000,37998)
assert (a['block_array_index_min'],a['block_array_index_max'])==(0,998)
assert a['original_form_branch_rows_sha256']=='be5b21ef2c8f8299dace1e14cf9f5e87dedee6515a2237627897fc8e6de480cb'
assert a['prior_all_formidx_occurrence_index_sha256']==prev['observed']['complete_7214_value_occurrence_index_sha256']
assert len([x for x in m['sources'] if x['source_id']=='RESPANEL-001' and x['sha256']==p['sha256']])==1
assert len([x for x in m['sources'] if x['source_id']=='DLL-001' and x['sha256']==d['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0358' and x['runtime_eligible'] is False])==1
assert not r['runtime_unlocked']
print('FACT-0358 exact original DLL GetFormData source and original source form index branch summary PASS')
