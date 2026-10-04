#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FAB
RVA=0x002F60DA
ROW='da602f0000008100fd350a00ebcd0200c63a'
SIG='20020111a7d808'
FLAGS=0x0081
HEADER=0x46
BODY=bytes.fromhex('021f1a04289d4f000602037d4e6100042a')
SHA='d693e192b2928d1a36497d9296bc697e14ada6ab9d936c6cbc1134813b9d07e5'

PARAMS=[
 (1,'kind','0000010063510100'),
 (2,'tm','00000200d7610700')
]
COUNTERATK_RID=2550
COUNTERATK_ROW='03010000a7790000000000004503b0612d50'

FIELD=0x0400614E
FIELD_ROW='0100dbf2030001000000'
FIELD_SIG='0608'
FIELD_DIGEST='d5718d050bd7e511e13bf4a3689b08e71f09a2eb9147f8bf1ef35f45a30e95ca'

CHILD=0x06004F9D
CHILD_SHA='58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065'
CALL_DIGEST='50353803322a8a677c90ee71b786cfc1ce6d91e5b879abd11fb8eedc3e1f0c3b'

EXPECTED_REFS=[
 {
  'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'ChangeCounter',
  'caller_token':'0x06004FDA','caller_rva':'0x002F92EC','caller_code_size':339,
  'caller_code_sha256':'ee3271363d38d319d290e669bdfc8d1c1f0e39de5ca6edc80bbec01e08f65a5d',
  'call_il':'0x014D','opcode':'call'
 },
 {
  'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_AfterHammerThrow',
  'caller_token':'0x06004FF2','caller_rva':'0x002FB3C0','caller_code_size':248,
  'caller_code_sha256':'f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3',
  'call_il':'0x00C2','opcode':'call'
 },
 {
  'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_AfterHammerThrow',
  'caller_token':'0x06004FF2','caller_rva':'0x002FB3C0','caller_code_size':248,
  'caller_code_sha256':'f417f4eab0e62c6e31057c8c5123b17c930240b8a0691685c70a1fc40ca4e7d3',
  'call_il':'0x00EC','opcode':'call'
 }
]
REF_DIGEST='86fa6e16dce76a7daf1b77e738cbdb944ac56ad2954786f05623e79b23ade63b'
CALLER_DIGEST='1c1be4e722be0dbceacee720cd826f221dd476a2e63c74fa28ad06be47e55435'

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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'SetAIAct_Counter',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    next_plist=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)[6]
    if next_plist-plist!=2: raise E('parameter count')

    for idx,(seq,nm,rowhex) in enumerate(PARAMS):
        rid=plist+idx
        p=o[8]+(rid-1)*z[8]
        rawp=pe[p:p+z[8]]
        fl=struct.unpack_from('<H',rawp,0)[0]
        sq=struct.unpack_from('<H',rawp,2)[0]
        q2=p+4
        ni,_=base.rd(pe,q2,s)
        if (rawp.hex(),fl,sq,base.s_at(pe,sb,ni))!=(rowhex,0,seq,nm):
            raise E('parameter '+str(seq))

    tp2=o[2]+(COUNTERATK_RID-1)*z[2]
    tr=pe[tp2:tp2+z[2]]
    q2=tp2+4
    ni,q2=base.rd(pe,q2,s); nsi,q2=base.rd(pe,q2,s)
    if tr.hex()!=COUNTERATK_ROW or base.s_at(pe,sb,ni)!='CounterAtkEnum' or base.s_at(pe,sb,nsi)!='':
        raise E('CounterAtkEnum metadata')

    ho=base.off(ss,RVA)
    if pe[ho]!=HEADER: raise E('tiny header')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    if drop.field(pe,s,b,z,o,sb,bb,fm,FIELD)!=(FIELD_ROW,('PlayerController_AI',''),'aiActPrm',FIELD_SIG):
        raise E('aiActPrm field')
    if body[0x000B]!=0x7d or struct.unpack_from('<I',body,0x000C)[0]!=FIELD:
        raise E('aiActPrm write')
    fa=[{'il':'0x000B','opcode':'stfld','token':'0x0400614E'}]
    if hashlib.sha256(json.dumps(fa,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=FIELD_DIGEST:
        raise E('field digest')

    if body[0:4]!=bytes.fromhex('021f1a04'): raise E('raw SetAIAct arguments')
    got=drop.calls(body)
    if got!=[(0x0004,0x28,CHILD)]: raise E('call surface '+repr(got))
    cm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if cm[4]!='SetAIAct' or cm[7]!=('PlayerController_AI','') or len(cm[9])!=102 or hashlib.sha256(cm[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0043 child identity')
    core=[{'il':'0x0004','opcode':'call','token':'0x06004F9D'}]
    if hashlib.sha256(json.dumps(core,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=CALL_DIGEST:
        raise E('call digest')
    if body[0x0009:0x0011]!=bytes.fromhex('02037d4e6100042a'):
        raise E('kind write/return')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256(''.join(x+'\n' for x in callers).encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)

    return {
      'code_size':17,'code_sha256':SHA,
      'canonical_internal_methoddef_reference_count':1,
      'external_memberref_method_call_count':0,
      'direct_reference_count':3,'direct_caller_method_count':2,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.SetAIAct_Counter':0,
      'PlayerController_AI.SetAIAct':0,
      'PlayerController_AI.ChangeCounter':0,
      'PlayerController_AI.Process_OpponentStands_AfterHammerThrow':0
    }
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
    a=argparse.ArgumentParser()
    a.add_argument('--dll',required=True)
    a.add_argument('--r6',required=True)
    x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_COUNTER: FAIL')
        print(str(e))
        return 1

if __name__=='__main__': raise SystemExit(main())
