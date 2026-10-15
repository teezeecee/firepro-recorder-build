"""FACT-0348 source-only original-byte relation and original retail DLL offset witnesses."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_first_record_byte_relations.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0348-original-fpw-first-record-byte-relations.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
o=w['observed'];d=w['dll'];p=w['panel']
assert f['fact_id']=='FACT-0348' and f['status']=='PROVEN_PACKED_DATA' and len(f['evidence'])==2 and len(f['chain_edges'])==2
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert w['dataset_id']=='UNITY_FPW440_RSF_FIRST_RECORD_BYTE_RELATIONS_DLL_BRIDGE_V1'
assert (p['bytes'],p['sha256'])==(330116,'0fdcac6e1b83c237de0b7f867cff3d61f7d97831efe08be9e4dcece346ba5b53')
assert (o['sample_count'],o['min_embedded_bytes'],o['max_embedded_bytes'])==(440,148,2488)
assert (o['offset_48_equals_offset_64_plus_one'],o['bytes_8_9_equal_bytes_69_70'],o['bytes_10_11_equal_bytes_72_73'])==(440,440,440)
assert o['normalized_440_byte_relation_index_sha256']=='6f72f25de972c0e4f532c6031f72aa7a6e996cd5414bfcc3480581be1b4b1094'
assert (o['variant_families'],o['two_variant_families'],o['three_variant_families'],o['total_suffixed_objects'],o['standalone_objects'])==(65,58,7,137,303)
assert o['within_each_family_embedded_length_equal'] is True
assert (d['original_size'],d['original_sha256'],d['methoddef'])==(8171008,'9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6','0x0600525F')
assert d['il_sha256']=='09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae'
assert d['parser_source_offsets']=={'initial_byte_reads':[10,11],'anm_num_source_array':[48,63],'first_entry_field_formNum':64,'first_entry_field_hitSE':69,'first_entry_field_cheerLevel':70,'first_entry_cursor_skips':[71,72,73]}
assert len(w['anchors'])==3 and [x['name'] for x in w['anchors']]==['fpw_2004_0','fpw_6172','fpw_6261']
assert any(s['source_id']=='RESPANEL-001' and s['sha256']==p['sha256'] for s in m['sources'])
assert any(s['source_id']=='DLL-001' and s['sha256']==d['original_sha256'] for s in m['sources'])
a=[x for x in r['families'] if x['fact_id']=='FACT-0348']
assert len(a)==1 and a[0]['runtime_eligible'] is False and r['runtime_unlocked'] is False
entry=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_anm_entry_fields_cursor_gap.summary.json').read_text())['dll']
fields={v['name']:v['source'] for v in entry['window']['fields'] if isinstance(v['source'],int)}
assert (fields['formNum'],fields['hitSE'],fields['cheerLevel'])==(64,69,70)
src=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json').read_text())['dll']
assert (src['window']['first_relative_input_byte'],src['window']['last_relative_input_byte'])==(48,63)
print('FACT-0348 original 440 RS source-byte relations and original IL locations PASS')
