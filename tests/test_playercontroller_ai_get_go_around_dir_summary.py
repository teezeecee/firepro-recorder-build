#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
s=json.loads((ROOT/'canonical'/'witnesses'/'CAP-R6-001'/'playercontroller_ai_get_go_around_dir.summary.json').read_text(encoding='utf-8'))
assert s['dataset_id']=='DLL_PLAYERCONTROLLER_AI_GET_GO_AROUND_DIR_V1' and s['source_ids']==['DLL-001']
d=s['dll'];m=d['method']
assert (m['token'],m['rva'],m['methoddef_row_hex'],m['signature_blob_hex'])==('0x06004FD7','0x002F9114','14912f0000008100d6390a0031cf0200ce3a','200011a7dc')
assert (m['impl_flags_raw'],m['method_attributes_raw'],m['fat_header_hex'],m['max_stack'],m['local_signature_token'],m['local_signature_row_hex'],m['local_signature_blob_hex'],m['parameter_count'])==('0x0000','0x0081','133002007e0000008e020011',2,'0x1100028E','6b940100','070112a788',0)
assert m['code_size']==126
assert hashlib.sha256(bytes.fromhex(m['body_hex'])).hexdigest()==m['code_sha256']=='6b1b83ca72c103a69a8f1ee79dfef7e6d7024e829b9a338b9589b198d118ab10'
assert [(x['token'],x['name']) for x in d['fields']]==[('0x040061FA','inst'),('0x0400614A','PlObj'),('0x04005FB1','TargetPlIdx'),('0x04005FAA','PlPos')]
assert [(x['token'],x['metadata_name'],x['signature_blob_hex']) for x in d['memberref_fields']]==[('0x0A000009','x','060c'),('0x0A00000A','y','060c')]
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':')).encode()).hexdigest()
assert len(d['field_accesses'])==12 and digest(d['field_accesses'])==d['normalized_field_access_map_sha256']=='a48fdfad43d24078fde692cf854dc544d7e73db494ab9acdaf097ffaecfc34af'
assert [(x['il'],x['token']) for x in d['memberref_field_accesses']]==[('0x0021','0x0A00000A'),('0x002C','0x0A00000A'),('0x0041','0x0A000009'),('0x004C','0x0A000009'),('0x0065','0x0A000009'),('0x0070','0x0A000009')]
assert digest(d['branches'])==d['normalized_branch_map_sha256']=='89168870fe4dce524cadca483afbac2b8e65d3c62afc3b68265e6c74d42ec1a2'
assert d['branches']==[{'il':'0x0031','opcode':'blt.un','target':'0x005A'},{'il':'0x0051','opcode':'bgt.un','target':'0x0058'},{'il':'0x0075','opcode':'bgt.un','target':'0x007C'}]
assert d['canonical_internal_calls']==[{'il':'0x0010','opcode':'callvirt','token':'0x06005065','owner':'PlayerMan','method':'GetPlObj','canonical_fact_id':'FACT-0109','child_code_size':25,'child_code_sha256':'32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'}]
assert d['memberref_method_calls']==[] and d['normalized_internal_call_map_sha256']=='13b4ef5227d073a59ac75ece81a4948af794e5f04580d44e10d275866565883c'
rr=d['direct_in_assembly_references']
assert [(x['caller_token'],x['call_il']) for x in rr]==[('0x06004FB0','0x000D'),('0x06004FB1','0x0036')]
assert len(rr)==d['direct_reference_count']==d['direct_caller_method_count']==2
assert digest(rr)==d['normalized_reference_map_sha256']=='f0445964c004ae70ce4d578835e89c0356d8bf43e0f3d6b184548137d8095a60'
assert hashlib.sha256(('0x06004FB0\n0x06004FB1\n').encode()).hexdigest()==d['normalized_caller_token_set_sha256']=='f5ba886b8ff566cd53e8d0c9c16e7ae72eabe7372dcc5f3bc427e9576e777540'
assert s['capture_boundary']['event_trace_sha256']=='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'
assert all(v==0 for k,v in s['capture_boundary'].items() if k.endswith('_row_count'))
assert s['capture_boundary']['promoted_as_evidence'] is False
assert s['selection_boundary']['only_methoddef_child']=='FACT-0109'
print('DLL PLAYERCONTROLLER AI GET GO AROUND DIR SUMMARY: PASS')
