#!/usr/bin/env python3
"""Prove FACT-0365 from user-owned raw original IL witness, without executing Unity."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'canonical/witnesses/DLL-001/original_rff_gettexcellidx_direct_callers_partsnum.summary.json'
def sha(data):return hashlib.sha256(data).hexdigest()
def ck(ok,msg):
    if not ok:raise AssertionError(msg)
def prove(path,s):
    raw=Path(path).read_bytes()
    ck((len(raw),sha(raw))==(s['private_witness']['bytes'],s['private_witness']['sha256']),'original private witness hash')
    w=json.loads(raw.decode('utf-8'))
    ck(w['schema_version']==1 and w['frontier']=='FACT-0365' and w['parent_fact']=='FACT-0364','source provenance')
    ck((w['dll_size_bytes'],w['dll_sha256'])==(s['original_dll']['bytes'],s['original_dll']['sha256']),'original DLL identity')
    ck(w['counted_methoddef_rows']==s['original_dll']['methoddef_rows_scanned']==30862,'original method scan count')
    methods=w['methods']; ck(len(methods)==2 and len(s['method_bodies'])==2,'two observed original source bodies')
    bodies={}
    for a,e in zip(methods,s['method_bodies']):
        b=bytes.fromhex(a['il_hex'])
        ck((a['name'],a['token'],a['il_length'],a['il_sha256'])==(e['name'],e['token'],e['bytes'],e['sha256']),'original MethodDef metadata')
        ck(sha(b)==a['il_sha256'] and len(b)==a['il_length'],'original complete IL SHA')
        pos=e['call_opcode_offset']
        ck(b[pos:pos+5]==bytes.fromhex('28 18 1f 00 06'),'actual original direct call opcode and MethodDef operand')
        ck(b.count(bytes.fromhex('28 18 1f 00 06'))==1,'one direct call per observed source body')
        bodies[a['name']]=b
    ck(w['exact_call_opcode_hits']==[{'token':m['token'],'name':m['name'],'call_opcode_offset':m['call_opcode_offset']} for m in s['method_bodies']],'original bounded call hits')
    for spec in s['source_windows']:
        b=bodies[spec['method']]
        ck(sha(b[spec['start']:spec['end']])==spec['sha256'],'original SHA source window '+spec['name'])
    l=bodies['LoadFormData'];p=bodies['ParseFormData_RFF']
    ck(l[289:307]==bytes.fromhex('11 09 7c c0 26 00 04 11 09 7c c1 26 00 04 28 18 1f 00 06')[-18:],'Load original two field address references + call')
    ck(p[156:174]==bytes.fromhex('11 08 7c c0 26 00 04 11 08 7c c1 26 00 04 28 18 1f 00 06')[-18:],'RFF original two field address references + call')
    ck(p[86:89]==bytes.fromhex('16 13 06'),'original counter zero initialization')
    ck(p[174:193]==bytes.fromhex('11 08 7b c1 26 00 04 16 3f 06 00 00 00 11 06 17 58 13 06'),'original cellIdx comparison and conditional increment')
    ck(182+5+struct.unpack_from('<i',p,183)[0]==193,'original bgt true target skips increment')
    ck(p[1127:1136]==bytes.fromhex('11 05 11 06 7d cb 26 00 04'),'original local6 to FormData.partsNum store')
    ck(p.count(bytes.fromhex('13 06'))==2 and p.count(bytes.fromhex('11 06'))==2,'original counter write/read paths')
    return {'fact':'FACT-0365','method_tokens':[m['token'] for m in methods],'consumer_call_offsets':[302,169],'parser_nonpositive_counter_to_partsnum':True,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--original-witness',required=True)
    a=ap.parse_args();print(json.dumps(prove(a.original_witness,json.loads(S.read_text())),sort_keys=True))
    print('FACT0365_ORIGINAL_RFF_CONSUMER_SOURCE_PASS')
