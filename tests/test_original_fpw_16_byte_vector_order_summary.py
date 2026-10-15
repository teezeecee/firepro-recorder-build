"""FACT-0349 original RS 16-source-byte ordering; no playback or asset bytes checked into Git."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESPANEL-001/original_440_fpw_16_byte_vector_order.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0349-original-fpw-16-byte-vector-order.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
p=w['original_panel'];d=w['original_dll'];o=w['observed']
assert f['fact_id']=='FACT-0349' and f['status']=='PROVEN_PACKED_DATA'
assert len(f['evidence'])==2 and len(f['chain_edges'])==2
assert set(x['source_id'] for x in f['evidence'])==set(w['source_ids'])=={'RESPANEL-001','DLL-001'}
assert w['dataset_id']=='UNITY_FPW440_RSF_16_SOURCE_BYTE_VECTOR_ORDER_AND_VARIANT_IDENTITY_V1'
assert (p['bytes'],p['sha256'])==(330116,'0fdcac6e1b83c237de0b7f867cff3d61f7d97831efe08be9e4dcece346ba5b53')
assert p['report_sha256']=='034dada3887209542c37d9cf704345868661564b0e7a6b758f4b58e7a99c0cfc'
assert (o['source_objects'],o['full_16_byte_vectors_non_decreasing'],o['full_16_byte_vectors_constant'],o['full_16_byte_vectors_some_increase'],o['byte_offsets_57_to_63_constant_within_each_vector'])==(440,440,55,385,440)
assert (o['distinct_16_byte_vectors'],o['suffixed_family_count'],o['suffixed_variant_count'])==(273,65,137)
assert (o['suffixed_two_variant_families'],o['suffixed_three_variant_families'])==(58,7)
assert o['all_65_families_have_identical_16_byte_vectors'] and o['all_65_families_have_equal_embedded_source_length']
assert (o['min_vec_first'],o['max_vec_first'],o['min_vec_maximum'],o['max_vec_maximum'])==(4,94,7,202)
assert o['original_vec48_63_concatenated_sha256']=='69a4dc4d349e75d5d011e41ea18d9e801fad19851a7424d4b937062edfcaa295'
assert o['indexed_440_vec_rows_sha256']=='4798483892af5369892ecf0ecdd62f1a12ad43aa7f6cfe05df36f33d7d2be6d0'
assert d['sha256']=='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
assert d['full_il_sha256']=='09000cc6b6e149540eb76d0865d8dd3aadcab1cd6bf8493286db768377c18cae'
assert (d['source_byte_start'],d['source_byte_end_exclusive'],d['source_byte_count'])==(48,64,16)
assert d['IL_read_window_sha256']=='9341a572133ddfaaab1be56708be076289f15ca2c03a3845073a1e78c396b690'
assert not d['runtime_linkage_proven']
assert len(w['anchors'])==3 and [x['name'] for x in w['anchors']]==['fpw_2004_0','fpw_6172','fpw_6261']
assert len([s for s in m['sources'] if s['source_id']=='RESPANEL-001' and s['sha256']==p['sha256']])==1
assert len([s for s in m['sources'] if s['source_id']=='DLL-001' and s['sha256']==d['sha256']])==1
assert len([x for x in r['families'] if x['fact_id']=='FACT-0349' and x['runtime_eligible'] is False])==1
assert r['runtime_unlocked'] is False
prior=json.loads((R/'canonical/witnesses/CAP-R6-001/skill_data_man_rsf_sixteen_anmnum_source_loop.summary.json').read_text())['dll']
assert prior['window']['first_relative_input_byte']==48 and prior['window']['last_relative_input_byte']==63
print('FACT-0349 original 440 sixteen-byte source vector ordering PASS')
