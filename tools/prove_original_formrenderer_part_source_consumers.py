#!/usr/bin/env python3
"""Verify FACT-0366 from the user's private original IL witness, without executing DLL code."""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SUMMARY=ROOT/'canonical/witnesses/DLL-001/original_formrenderer_part_source_consumers.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(c,msg):
    if not c:raise AssertionError(msg)
def prove(path,s):
    raw=Path(path).read_bytes()
    ck((len(raw),sha(raw))==(s['private_witness']['bytes'],s['private_witness']['sha256']),'exact original private witness SHA')
    w=json.loads(raw.decode('utf-8-sig'))
    ck((w['schema_version'],w['parent_fact'],w['frontier'])==(1,'FACT-0365','FACT-0366'),'provenance')
    ck((w['original_dll_size'],w['original_dll_sha256'])==(s['original_dll']['bytes'],s['original_dll']['sha256']),'original DLL SHA')
    ck(len(w['methods'])==len(s['source_method_bodies'])==3,'three original methods')
    bodies={}
    for a,e in zip(w['methods'],s['source_method_bodies']):
        b=bytes.fromhex(a['il_hex'])
        ck(all(a[k]==e[k] for k in ('token','owner','name','il_length','il_sha256')),'original method metadata')
        ck(len(b)==e['il_length'] and sha(b)==e['il_sha256'],'exact original IL SHA')
        bodies[e['name']]=b
    ck(len(w['exact_source_windows'])==len(s['source_windows'])==7,'seven bounded source windows')
    for a,e in zip(w['exact_source_windows'],s['source_windows']):
        ck(a==e,'original window metadata')
        ck(sha(bodies[e['method']][e['start']:e['end']])==e['sha256'],'original source window SHA '+e['name'])
    ck([(f['token'],f['name']) for f in w['exact_field_metadata']]==[(f['token'],f['name']) for f in s['original_fields']],'original field metadata')
    p=bodies['SetPartsObj'];c=bodies['CalcPartsOffset'];k=bodies['TexKind2PartsKind']
    def operand(b,off,opcode,token):
        ck(b[off]==opcode and struct.unpack_from('<I',b,off+1)[0]==int(token,16),'original exact opcode/operand at '+str(off))
    operand(p,2,0x7b,'0x040026C0')
    operand(p,7,0x28,'0x06001F3E')
    ck(p[15]==0x3c and struct.unpack_from('<i',p,16)[0]==1 and p[20]==0x2a,'nonnegative partsKind guard source')
    for off,token in [(144,'0x040026C0'),(150,'0x040026C1'),(163,'0x040026C0'),(169,'0x040026C1')]:operand(p,off,0x7b,token)
    operand(p,155,0x28,'0x06001F29')
    operand(p,178,0x28,'0x06001F1C')
    for off,token in [(0,'0x0400271D'),(18,'0x0400271D'),(36,'0x0400271E'),(54,'0x0400271E')]:operand(c,off,0x7e,token)
    ck(k[3]==0x45 and struct.unpack_from('<I',k,4)[0]==9,'original nine-case switch')
    return {'fact':'FACT-0366','verified_original_methods':list(bodies),'original_source_windows':7,'runtime_eligible':False}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--original-witness',required=True)
    a=parser.parse_args();print(json.dumps(prove(a.original_witness,json.loads(SUMMARY.read_text())),sort_keys=True))
    print('FACT0366_ORIGINAL_FORMRENDERER_SOURCE_PASS')
