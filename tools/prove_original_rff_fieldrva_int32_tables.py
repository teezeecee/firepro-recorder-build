#!/usr/bin/env python3
"""Read-only proof of FACT-0364 from the user's own original Fire Pro DLL.
The original integer values never belong in Git; optional --output writes them locally.
"""
import argparse,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'canonical/witnesses/DLL-001/original_rff_fieldrva_int32_tables.summary.json'
def sha(b):return hashlib.sha256(b).hexdigest()
def ck(v,m):
    if not v:raise AssertionError(m)
def prove(path,w):
    raw=Path(path).read_bytes()
    ck(len(raw)==w['original_dll']['bytes'] and sha(raw)==w['original_dll']['sha256'],'exact original DLL identity')
    ck(raw[:2]==b'MZ','original PE DOS header')
    pe=struct.unpack_from('<I',raw,0x3c)[0]
    ck(raw[pe:pe+4]==bytes([80,69,0,0]),'original PE signature')
    n=struct.unpack_from('<H',raw,pe+6)[0]; size=struct.unpack_from('<H',raw,pe+20)[0]
    sections=[]
    for i in range(n):
        p=pe+24+size+40*i
        sizevirt,addr,rawsize,rawaddr=struct.unpack_from('<IIII',raw,p+8)
        sections.append((addr,max(sizevirt,rawsize),rawaddr,rawsize))
    def to_file(rva):
        for va,size,off,rawlen in sections:
            if va<=rva<va+size:
                ck(rva-va<rawlen,'not mapped to raw bytes')
                return off+rva-va
        raise AssertionError('invalid PE RVA')
    results=[]
    f=w['embedded_sources']; ck(len(f)==8,'eight source fields')
    for i,s in enumerate(f):
        off=w['metadata']['first_fieldrva_record_file_offset']+i*w['metadata']['row_size']
        rva,rid=struct.unpack_from('<IH',raw,off)
        ck(s['fieldrva_row']==175+i and s['source_field_token']==f'0x{(0x0400B7AA+i):08X}','metadata FieldDef/source order')
        ck(rva==s['rva'] and rid==int(s['source_field_token'],16)&0xffffff,'original FieldRVA table row')
        ck(to_file(rva)==s['file_offset'] and s['byte_count']==4*s['element_count'],'original PE RVA-byte offset and size')
        block=raw[s['file_offset']:s['file_offset']+s['byte_count']]
        ck(len(block)==s['byte_count'] and sha(block)==s['sha256'],'original int32 raw byte SHA')
        vals=list(struct.unpack('<'+'i'*s['element_count'],block))
        ck((min(vals),max(vals),vals.count(-1))==(s['min'],s['max'],s['minus_one_count']),'original numeric inventory')
        ck(all(v>=-1 for v in vals),'unexpected negative integer')
        ck(len([v for v in vals if v>=0])==len(set(v for v in vals if v>=0)),'original nonnegative uniqueness')
        results.append({'token':s['source_field_token'],'values':vals,'sha256':sha(block)})
    m=w['nine_destination_arrays']
    ck(len(m)==9 and sum(x['element_count'] for x in m)==573,'original destination counts')
    ck(m[1]['source_field_token']==m[3]['source_field_token'],'original Chest/UpperArm source identity')
    ck(sum(s['element_count'] for s in f)==w['unique_backing_entries']==522,'unique source element count')
    return {'status':'PRIVATE_USER_SOURCE_WITNESS_NO_PROMOTION','fact':'FACT-0364','original_sha256':sha(raw),'source_arrays':results,'destination_tables':m,'runtime_eligible':False}
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--original-dll',required=True)
    ap.add_argument('--output',help='optional private local JSON (create-new only)')
    arg=ap.parse_args(); report=prove(arg.original_dll,json.loads(S.read_text()))
    if arg.output:
        p=Path(arg.output); ck(not p.exists(),'output exists (refusing overwrite)')
        with p.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
        print('PRIVATE ORIGINAL VALUES SAVED:',p)
    print('FACT0364_ORIGINAL_FIELDRVA_SOURCE_PASS',report['original_sha256'],len(report['source_arrays']))
