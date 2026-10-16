"""FACT-0361 pinned original 1153-byte parser IL structural stride summary; runtime remains locked."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
s=json.loads((R/'canonical/witnesses/DLL-001/original_fprform_rff_parser_il_stride.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0361-original-formdata-rff-parser-20x16-stride.json').read_text())
reg=json.loads((R/'canonical/transition_registry.json').read_text())
prior=json.loads((R/'canonical/witnesses/RESOBJ-003/original_fprform_rff_body_sha_and_embedded_bytes.summary.json').read_text())
loader=json.loads((R/'canonical/witnesses/RESMETA-001/original_fprform_rff_ggm_loader_join.summary.json').read_text())
assert f['fact_id']=='FACT-0361' and f['status']=='CORROBORATED_MULTI_SOURCE'
assert {e['source_id'] for e in f['evidence']}==set(s['source_ids'])=={'DLL-001','RESOBJ-003'}
a=s['original_parser'];st=s['source_stride'];res=s['exact_resource_match']
assert (a['parser_il_bytes'],a['max_stack'],a['exception_clause_count'])==(1153,5,0)
assert a['parent_loader_il_sha256']==loader['original_dll']['loader']['body_sha256']
assert a['original_dll_sha256']==loader['original_dll']['sha256']
assert a['parser_il_sha256']=='f8cd8fc00b94298c4d9949c461f5ab0e0f2c736befed5eb9305e5f39a10e1b01'
assert len(a['windows'])==5 and a['windows'][0]['start']==0 and a['windows'][-1]['end']==1153
assert all(a['windows'][i]['end']==a['windows'][i+1]['start'] for i in range(4))
assert len(st['ldelem_u1_il_offsets'])==13 and st['per_inner_stride_bytes']==st['per_inner_source_bytes_read']+st['per_inner_explicit_cursor_skip']==16
assert st['inner_entries_per_outer']==20 and st['source_bytes_per_form']==320
assert st['source_allocated_form_array_elements']==loader['original_dll']['loader']['instructions']['form_array_length_constant']==37999
assert st['source_outer_iterations_if_executed']==37998
assert res['embedded_bytes']==prior['matching_export']['textasset_wrapper']['embedded_data_length']==12800000
assert res['embedded_sha256']==prior['matching_export']['textasset_wrapper']['embedded_data_sha256']
assert res['resource_sha256']==prior['matching_export']['sha256']
assert res['parser_conditional_bytes_consumed']==37998*320==12159360
assert res['remaining_unread_bytes_under_verified_loader_array_length']==640640 and res['remaining_320_byte_windows']==2002
assert len([x for x in reg['families'] if x['fact_id']=='FACT-0361' and x['runtime_eligible'] is False])==1
assert reg['runtime_unlocked'] is False
print('FACT-0361 original parser source-proven 20x16 stride static summary PASS')
