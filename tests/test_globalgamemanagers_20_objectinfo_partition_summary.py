"""FACT-0341 static original-source ObjectInfo partition guards."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
w = json.loads((ROOT/'canonical/witnesses/GGM-001/objectinfo_20_complete_payload_partition.summary.json').read_text())
f = json.loads((ROOT/'canonical/facts/FACT-0341-original-unity-objectinfo-complete-payload-partition.json').read_text())
reg = json.loads((ROOT/'canonical/transition_registry.json').read_text())
source = json.loads((ROOT/'canonical/source_manifest.json').read_text())

assert w['dataset_id']=='UNITY_GGM_20_OBJECTINFO_COMPLETE_PAYLOAD_PARTITION_V1'
assert f['fact_id']=='FACT-0341' and f['status']=='PROVEN_PACKED_DATA' and not f['chain_edges']
assert len(f['evidence'])==1 and f['evidence'][0]['source_id']=='GGM-001'
assert w['original_file']['sha256']=='04cf0c7a5ef858ce68ff5b00b7281ded8fc5b4efe84539d26c21799a4044c22c'
assert w['original_file']['bytes']==5002540 and w['original_file']['data_offset']==4096
m=w['metadata'];p=w['payload'];o=w['objects'];g=w['alignment_gaps']
assert m['class_id_order']==[129,13,78,11,94,116,30,5,98,55,141,47,147,149,155,126,19,300,301,310]
assert m['object_info_start']==504 and m['object_info_end']==904
assert m['object_info_sha256']=='affd2ea8a5b2fced4889c705d39c2ac369504d32201bae7aeb2648ee44c52f35'
assert (m['metadata_end'],m['post_metadata_zero_padding_start'],m['post_metadata_zero_padding_end'])==(1399,1399,4096)
assert p['start']==4096 and p['end']==5002540 and p['length']==4998444
assert p['sha256']=='5e56c7267ff6adac892537d6cfe898a7c239ba202179c4315afbe3de190b6d20'
assert p['sum_object_bytes']==4998401 and p['sum_gap_bytes']==43
assert p['object_bodies_in_order_sha256']=='5f9f89150502cd12f21d9b17ad48989ce93fe59b9f18430bb997fbf7fdd39997'
assert p['gap_bytes_in_order_sha256']=='859732b97382a08583d6a67f5842486505e50bee754bd9b57ac3abf81b9714f2'
assert p['object_body_count']==20 and p['nonempty_object_count']==17 and p['empty_object_count']==3
assert p['empty_path_ids']==[9,15,21] and len(o)==20
assert len(g)==p['gap_count']==9 and sum(x['bytes'] for x in g)==43 and p['all_gap_bytes_zero']
assert sum(x['byte_size'] for x in o)==4998401
assert [(x['path_id'],x['class_id']) for x in o if x['byte_size']==0]==[(9,98),(15,155),(21,301)]
assert all(x['hex']=='00'*x['bytes'] for x in g)
assert all(x['type_index']==x['object_index'] and x['class_id']==m['class_id_order'][x['type_index']] for x in o)
assert o[12]['path_id']==13 and o[12]['byte_size']==4862328
assert o[13]['path_id']==14 and o[13]['byte_size']==16532
assert o[-1]['absolute_offset']+o[-1]['byte_size']==5002540
assert len([x for x in reg['families'] if x['fact_id']=='FACT-0341'])==1
assert next(x for x in reg['families'] if x['fact_id']=='FACT-0341')['runtime_eligible'] is False
assert reg['runtime_unlocked'] is False
assert next(x for x in source['sources'] if x['source_id']=='GGM-001')['sha256']==w['original_file']['sha256']
print('FACT-0341 ORIGINAL 20 OBJECTINFO WINDOWS, 43 ZERO ALIGNMENT BYTES: PASS')
