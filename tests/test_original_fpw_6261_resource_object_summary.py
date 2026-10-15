"""FACT-0345 read-only original-body source evidence guards."""
import json
from pathlib import Path
R=Path(__file__).resolve().parents[1]
w=json.loads((R/'canonical/witnesses/RESOBJ-001/fpw_6261_exact_2376_byte_object.summary.json').read_text())
f=json.loads((R/'canonical/facts/FACT-0345-original-fpw6261-2376-byte-resource-object.json').read_text())
m=json.loads((R/'canonical/source_manifest.json').read_text())
r=json.loads((R/'canonical/transition_registry.json').read_text())
assert f['fact_id']=='FACT-0345' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert set(e['source_id'] for e in f['evidence'])==set(w['source_ids'])=={'RESOBJ-001','RESMETA-001','GGM-001'}
assert w['dataset_id']=='UNITY_RESOURCES_FPW6261_SINGLE_OBJECT_ORIGINAL_BYTES_V1'
o=w['object_source']; meta=w['metadata_source'];g=w['original_ggm_source'];l=w['original_object_layout']
assert (o['size_bytes'],o['sha256'])==(2376,'8ff30c94fc26ca7b914352dbf6b2a5add12429f36f14ac1450619cb0000f8401')
assert o['original_absolute_offset']==1960380520 and o['original_end_exclusive']==1960382896
assert o['original_full_container_sha_rechecked_in_extraction'] is False
assert meta['sha256']=='8388d7e2401172e5ee1139f617afeac8a68aaeb64383bc076098a922e45151da'
assert (meta['path_id'],meta['class_id'],meta['type_index'],meta['original_objectinfo_row_offset'])==(21624,49,4,449672)
assert (meta['object_relative_offset'],meta['object_byte_size'],meta['data_offset'])==(1958538296,2376,1842224)
assert meta['original_objectinfo_row_sha256']=='d927a3ca057dcecbd20b2b6e27db4376dd0634ab46b82fd02303ad858bc2d98b'
assert g['sha256']=='04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c'
assert (g['matched_index'],g['matched_file_id'],g['matched_path_id'])==(43940,5,21624)
assert g['matched_occurrence_count']==1 and g['matched_name']=='wrestleranimation/fpw_6261'
assert (l['name_length_u32'],l['name_ascii'],l['embedded_length_u32'])==(8,'fpw_6261',2356)
assert (l['embedded_bytes_start'],l['embedded_bytes_end'],l['terminal_four_bytes_end'])==(16,2372,2376)
assert l['embedded_bytes_sha256']=='4bd313481985bb951519a6173521b8276498c5a2834d8fb367eb5c75ee481c08'
assert l['first_two_embedded_bytes_hex']=='5253' and l['terminal_four_bytes_hex']=='00000000'
assert l['fully_accounted_bytes']==o['size_bytes']==4+8+4+2356+4
assert next(s for s in m['sources'] if s['source_id']=='RESOBJ-001')['sha256']==o['sha256']
assert next(s for s in m['sources'] if s['source_id']=='RESMETA-001')['sha256']==meta['sha256']
assert len([x for x in r['families'] if x['fact_id']=='FACT-0345'])==1
assert next(x for x in r['families'] if x['fact_id']=='FACT-0345')['runtime_eligible'] is False
assert r['runtime_unlocked'] is False
print('FACT-0345 VERIFIED 2376 ORIGINAL SOURCE BYTES AND EXACT GGM/PREFIX JOIN: PASS')
