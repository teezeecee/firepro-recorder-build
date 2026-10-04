#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004AA1
RVA=0x002B8318
ROW='18832b0000009600e2050a0002b302004537'
SIG='0005011d081d08080808'
FLAGS=0x0096
HEADER='13300600c4000000d1060011'
LOCAL_SIG_TOKEN=0x110006D1
LOCAL_SIG_ROW='9afc0100'
LOCAL_SIG_BLOB='07050808080808'
BODY=bytes.fromhex('050a0e040b02060758185b940c043a2900000038040000000617580a020694083ff3ffffff38040000000717590b020794083df3ffffff382400000038040000000617580a020694083df3ffffff38040000000717590b020794083ff3ffffff06073f05000000382b0000000206940d030694130402060207949e03060307949e0207099e030711049e0617580a0717590b3876ffffff050617593c0c0000000203040506175928a14a00060e040717583e0d0000000203040717580e0428a14a00062a')
SHA='14e7deca98e8fbf64b0564a069032b864cbea75e70eeabe0051e1091470c5718'

PARAMS=[
 (14149,'00000100ec510700',1,'sort_param'),
 (14150,'00000200f7510700',2,'sort_idx'),
 (14151,'0000030000520700',3,'asdes'),
 (14152,'0000040024100200',4,'first'),
 (14153,'000005006cc80000',5,'last')
]
REF_DIGEST='dadf2d5ce33ff219cc19f391ac05cc7499cc0983466534264f590ad22b4cb71f'
CALLER_DIGEST='6e22fe6addfd2305992cadf1ee3f15508915bf2eac08a5da5d00cb88d8050b24'
SHUFFLE_REF={
 'caller_type':'Misc','caller_namespace':'','caller_method':'Shuffle',
 'caller_token':'0x06004AA7','caller_rva':'0x002B8560','caller_code_size':65,
 'caller_code_sha256':'d8e87deae43facf68b16b094188ade6c7db1915caa3c59031cb85f891529b5c1',
 'call_il':'0x003B','opcode':'call'
}

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
    if (raw,rva,impl,flags,name,sig,plist,owner)!=(ROW,RVA,0,FLAGS,'QuickSort_Int',SIG,14149,('Misc','')):
        raise E('method metadata')
    if drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]!=14154: raise E('parameter range')
    if bytes.fromhex(sig)!=bytes.fromhex('0005011d081d08080808'): raise E('signature bytes')

    actual_params=[]
    for rid,row,seq,nm in PARAMS:
        p=o[8]+(rid-1)*z[8]
        rawp=pe[p:p+z[8]]
        if rawp.hex()!=row: raise E('Param row '+str(rid))
        flags_p=struct.unpack_from('<H',rawp,0)[0]
        seq_p=struct.unpack_from('<H',rawp,2)[0]
        ni,_=base.rd(pe,p+4,s)
        name_p=base.s_at(pe,sb,ni)
        if (flags_p,seq_p,name_p)!=(0,seq,nm): raise E('Param metadata '+str(rid))
        actual_params.append((rid,row,seq,nm))

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    fs=struct.unpack_from('<H',pe,ho)[0]
    if (fs&0xfff,struct.unpack_from('<H',pe,ho+2)[0],struct.unpack_from('<I',pe,ho+4)[0],struct.unpack_from('<I',pe,ho+8)[0])!=(0x13,6,196,LOCAL_SIG_TOKEN):
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    if pe[sp:sp+z[17]].hex()!=LOCAL_SIG_ROW: raise E('local signature row')
    si,_=base.rd(pe,sp,b)
    if base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB: raise E('local signature blob')

    if body[:13]!=bytes.fromhex('050a0e040b02060758185b940c'): raise E('initialization')
    for il,op,target in [
        (0x000E,0x3a,0x003C),(0x0020,0x3f,0x0018),(0x0032,0x3d,0x002A),
        (0x0049,0x3d,0x0041),(0x005B,0x3f,0x0053),(0x0062,0x3f,0x006C),
        (0x0067,0x38,0x0097),(0x0092,0x38,0x000D),(0x009B,0x3c,0x00AC),
        (0x00B1,0x3e,0x00C3)
    ]:
        if body[il]!=op or drop.target4(body,il)!=target: raise E('branch '+hex(il))
    if body[0x00A7]!=0x28 or struct.unpack_from('<I',body,0x00A8)[0]!=T: raise E('recursive call A')
    if body[0x00BE]!=0x28 or struct.unpack_from('<I',body,0x00BF)[0]!=T: raise E('recursive call B')
    if drop.calls(body)!=[(0x00A7,0x28,T),(0x00BE,0x28,T)]: raise E('call surface '+repr(drop.calls(body)))

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if len(rr)!=21 or len({x['caller_token'] for x in rr})!=20: raise E('reference counts')
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256((''.join(x+'\n' for x in callers)).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)
    if [x for x in rr if x['caller_method']=='Shuffle']!=[SHUFFLE_REF]: raise E('Shuffle reference')
    self_refs=[x for x in rr if x['caller_token']=='0x06004AA1']
    if [(x['call_il'],x['opcode']) for x in self_refs]!=[('0x00A7','call'),('0x00BE','call')]:
        raise E('self references')

    return {'code_size':196,'code_sha256':SHA,'recursive_methoddef_call_count':2,
            'external_memberref_method_call_count':0,'direct_reference_count':21,
            'direct_caller_method_count':20,'reference_map_sha256':rd}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'Misc.QuickSort_Int':0,'Misc.Shuffle':0,'PlayerController_AI.MakeRapidPushTbl':0}
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
        print('PROVE_MISC_QUICKSORT_INT: PASS'); return 0
    except Exception as e:
        print('PROVE_MISC_QUICKSORT_INT: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
