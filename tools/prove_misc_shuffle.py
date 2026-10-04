#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004AA7
RVA=0x002B8560
ROW='60852b00000096003a060a0029b302005b37'
SIG='0002011d0808'
FLAGS=0x0096
HEADER='13300600410000003a000011'
LOCAL_SIG_TOKEN=0x1100003A
LOCAL_SIG_ROW='f25a0100'
LOCAL_SIG_BLOB='070108'
BODY=bytes.fromhex('0320000100003e010000002a160a38160000007e3159000406162000000100287b4900069e0617580a06033fe3ffffff7e3159000402161603175928a14a00062a')
SHA='d8e87deae43facf68b16b094188ade6c7db1915caa3c59031cb85f891529b5c1'

PARAMS=[
 (14171,'000001001d000600',1,'a'),
 (14172,'00000200122b0100',2,'num')
]
FIELD=0x04005931
FIELD_ROW='1100ce9703008d030000'
FIELD_SIG='061d08'
FIELD_ACCESS=[
 (0x0013,'ldsfld',FIELD),
 (0x0030,'ldsfld',FIELD)
]
FIELD_ACCESS_DIGEST='e6ba82e635d388e5aa115a3d27cabaef6c0a579854af0a03b3796ea70a5da6eb'
CHILDREN=[
 (0x001F,0x28,0x0600497B,'MatchRandom','Range',30,'d6ed5dd5c1cdf595ca459ddc1c740ce66543e9630786cfdc9bf3404247f643f6'),
 (0x003B,0x28,0x06004AA1,'Misc','QuickSort_Int',196,'14e7deca98e8fbf64b0564a069032b864cbea75e70eeabe0051e1091470c5718')
]
CALL_DIGEST='feca82b4b783e3d3795c0db2e1cb632d5b075042b4148f1af978454a8df0248e'
EXPECTED_REFS=[{
 'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'MakeRapidPushTbl',
 'caller_token':'0x06004FD4','caller_rva':'0x002F8DC4','caller_code_size':308,
 'caller_code_sha256':'63b284583be3198f0647d16649fe43126b7f5c5d0b0c6a5c2ba73ad233530db7',
 'call_il':'0x00E9','opcode':'call'
}]
REF_DIGEST='512cb7970f8f6cfc59c8ef156984843b2f463ae89900bf16611cc6bbdcef606c'
CALLER_DIGEST='57c7e8247b57b3415421d95222f7f487d4cc22ba7443e55276dcd046ae08bb29'

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[(bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),
          (bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),
          (bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=md[9]
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({
                    'caller_type':md[7][0] if md[7] else None,
                    'caller_namespace':md[7][1] if md[7] else None,
                    'caller_method':md[4],
                    'caller_token':f'0x{tok:08X}',
                    'caller_rva':f'0x{md[1]:08X}',
                    'caller_code_size':len(body),
                    'caller_code_sha256':hashlib.sha256(body).hexdigest(),
                    'call_il':f'0x{x:04X}','opcode':opname
                })
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe)
    st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,plist,owner)!=(ROW,RVA,0,FLAGS,'Shuffle',SIG,14171,('Misc','')):
        raise E('method metadata')
    if drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=14173: raise E('parameter range')
    if bytes.fromhex(sig)!=bytes.fromhex('0002011d0808'): raise E('signature bytes')

    for rid,row,seq,nm in PARAMS:
        p=o[8]+(rid-1)*z[8]
        rawp=pe[p:p+z[8]]
        if rawp.hex()!=row: raise E('Param row '+str(rid))
        flags_p=struct.unpack_from('<H',rawp,0)[0]
        seq_p=struct.unpack_from('<H',rawp,2)[0]
        ni,_=base.rd(pe,p+4,s)
        if (flags_p,seq_p,base.s_at(pe,sb,ni))!=(0,seq,nm): raise E('Param metadata '+str(rid))

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    fs=struct.unpack_from('<H',pe,ho)[0]
    if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+4)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,6,65,LOCAL_SIG_TOKEN):
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    if pe[sp:sp+z[17]].hex()!=LOCAL_SIG_ROW: raise E('local signature row')
    si,_=base.rd(pe,sp,b)
    if base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB: raise E('local signature blob')

    f=drop.field(pe,s,b,z,o,sb,bb,fm,FIELD)
    if f!=(FIELD_ROW,('Misc',''),'rnd_prm',FIELD_SIG): raise E('rnd_prm field')
    amap=[]
    for il,opn,tok in FIELD_ACCESS:
        if body[il]!=0x7e or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opn,'token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_ACCESS_DIGEST:
        raise E('field access digest')

    if body[0]!=0x03 or body[1]!=0x20 or struct.unpack_from('<i',body,2)[0]!=256: raise E('num gate operands')
    if body[0x06]!=0x3e or drop.target4(body,0x06)!=0x000C or body[0x0B]!=0x2a: raise E('num gate branch')
    if body[0x0C:0x0E]!=bytes([0x16,0x0a]): raise E('local zero init')
    if body[0x0E]!=0x38 or drop.target4(body,0x0E)!=0x0029: raise E('loop initial branch')
    if not (body[0x19]==0x16 and body[0x1A]==0x20 and struct.unpack_from('<i',body,0x1B)[0]==65536):
        raise E('Range constants')
    if body[0x24]!=0x9e or body[0x25:0x29]!=bytes([0x06,0x17,0x58,0x0a]): raise E('loop store/increment')
    if body[0x2B]!=0x3f or drop.target4(body,0x2B)!=0x0013: raise E('loop comparison')
    if body[0x35:0x3B]!=bytes([0x02,0x16,0x16,0x03,0x17,0x59]): raise E('QuickSort arguments')

    actual_calls=drop.calls(body)
    if actual_calls!=[(x[0],x[1],x[2]) for x in CHILDREN]: raise E('call surface '+repr(actual_calls))
    call_core=[]
    for il,op,tok,own,nm,size,h in CHILDREN:
        cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if cm[4]!=nm or cm[7]!=(own,'') or len(cm[9])!=size or hashlib.sha256(cm[9]).hexdigest()!=h:
            raise E('child identity '+hex(tok))
        call_core.append({'il':f'0x{il:04X}','opcode':'call','token':f'0x{tok:08X}'})
    if hashlib.sha256(json.dumps(call_core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    cd=hashlib.sha256(('0x06004FD4\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {'code_size':65,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':2,
            'external_memberref_method_call_count':0,'direct_reference_count':1,
            'direct_caller_method_count':1,'reference_map_sha256':rd}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'Misc.Shuffle':0,'Misc.QuickSort_Int':0,'MatchRandom.Range':0,'PlayerController_AI.MakeRapidPushTbl':0}
    with zipfile.ZipFile(path) as zf:
        if zf.testzip(): raise E('CRC')
        names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1: raise E('event trace count')
        bts=zf.read(names[0])
        if hashlib.sha256(bts).hexdigest()!=EVENT_SHA: raise E('event trace identity')
        for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
            if row['method'] in wanted: wanted[row['method']]+=1
    if any(wanted.values()): raise E('R6 boundary '+repr(wanted))
    return dict(wanted,promoted_as_evidence=False)

def main():
    a=argparse.ArgumentParser(); a.add_argument('--dll',required=True); a.add_argument('--r6',required=True); x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_MISC_SHUFFLE: PASS'); return 0
    except Exception as e:
        print('PROVE_MISC_SHUFFLE: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
