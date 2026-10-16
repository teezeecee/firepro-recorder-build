#!/usr/bin/env python3
"""FACT-0363 original DLL static cell table initializer source-only prover."""
import argparse, hashlib, json, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'canonical/witnesses/DLL-001/original_rff_static_cell_tables_initializer.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(cond,msg):
    if not cond:raise AssertionError(msg)
def prove(path,w):
    raw=Path(path).read_bytes()
    ck((len(raw),sha(raw))==(w['witness']['bytes'],w['witness']['sha256']),'original witness SHA')
    a=json.loads(raw.decode('utf-8-sig'))
    ck((a['schema_version'],a['status'],a['parent_canonical_fact'],a['requested_frontier'])==(1,'ORIGINAL_SOURCE_FIELD_METADATA_WITNESS_ONLY_NOT_CANONICAL_FACT','FACT-0362','FACT-0363'),'original provenance')
    for k,v in w['original_dll'].items():ck(a[k]==v,'original DLL source identity '+k)
    f=a['nine_lookup_field_tokens'];ck(len(f)==len(w['fields'])==9,'nine fields')
    for observed,expected in zip(f,w['fields']):
        ck(observed['status']=='RESOLVED_METADATA','original resolved metadata')
        ck(all(observed[k]==v for k,v in [('token',expected['token']),('name',expected['name']),('owner','FormDataMan'),('field_type','System.Int32[]'),('is_static',True),('is_literal',False),('is_init_only',False)]),'original field source '+expected['token'])
    h=a['formdataman_type_initializer'];p=w['initializer']
    ck(h['exists'] is True and h['metadata_token']==p['metadata_token'] and h['il_bytes']==208,'initializer identity')
    b=bytes.fromhex(h['il_hex']);ck(len(b)==208 and sha(b)==h['il_sha256']==p['sha256'],'full original IL byte SHA')
    ck(b[-1]==0x2a,'return opcode')
    ck(len(p['blocks'])==9 and sum(x['size'] for x in p['blocks'])==p['total_elements']==573,'source lengths')
    for i,block in enumerate(p['blocks']):
        v=b[i*23:(i+1)*23]
        ck(sha(v)==block['sha256'],'contiguous 23-byte original IL source window')
        ck((v[0],v[2],v[7],v[8],v[13],v[18])==(0x1f,0x8d,0x25,0xd0,0x28,0x80),'array setup / source / call / store')
        ck(v[1]==block['size'],'original length operand')
        ck(struct.unpack_from('<I',v,3)[0]==int(p['type_element_token'],16),'source Int32 array element token')
        ck(struct.unpack_from('<I',v,9)[0]==int(block['original_data_field_token'],16),'original data FieldDef token')
        ck(struct.unpack_from('<I',v,14)[0]==int(p['initializer_memberref_token'],16),'original call MemberRef')
        ck(struct.unpack_from('<I',v,19)[0]==int(block['dest_token'],16)==int(f[i]['token'],16),'destination FieldDef')
    ck(a['scanned_declared_methods']==w['source_method_scan']['declared_methods_scanned']==14,'scanned source methods')
    candidates=a['direct_field_opcode_method_candidates']
    ck(len(candidates)==2,'two exact field opcode method candidates')
    for method,expected in zip(candidates,w['source_method_scan']['direct_field_opcode_methods']):
        raw_il=bytes.fromhex(method['il_hex'])
        ck(method['method_token']==expected['token'] and method['il_sha256']==expected['il_sha256']==sha(raw_il),'source method full SHA')
        op=0x7e if expected['opcode']=='ldsfld' else 0x80
        ck(len(method['direct_field_opcode_candidates'])==9,'nine instruction references')
        for i,ref in enumerate(method['direct_field_opcode_candidates']):
            pos=ref['opcode_offset'];ck(raw_il[pos]==op and ref['operand_offset']==pos+1,'actual original instruction opcode')
            ck(struct.unpack_from('<I',raw_il,pos+1)[0]==int(f[i]['token'],16) and ref['field_token']==f[i]['token'],'source field reference')
    return {'fact':'FACT-0363','initializer_sha256':sha(b),'source_arrays':9,'elements_allocated':573,'actual_table_values_extracted':False,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--original-witness',required=True);arg=ap.parse_args()
    print(json.dumps(prove(arg.original_witness,json.loads(S.read_text())),sort_keys=True))
    print('FACT0363_ORIGINAL_STATIC_TABLE_IL_SOURCE_PASS')
