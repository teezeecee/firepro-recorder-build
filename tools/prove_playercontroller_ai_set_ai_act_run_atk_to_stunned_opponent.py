#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FA9
RVA=0x002F60B6
ROW='b6602f0000008100c5350a00e3cd0200c23a'
SIG='20020111a7d008'
FLAGS=0x0081
HEADER=0x46
BODY=bytes.fromhex('021f0f04289d4f000602037d4e6100042a')
SHA='14e962309d03585018de393653c8b4dd4508649084262fbd1bff8fcd9a70e49f'
PARAM_ROWS=['0000010063510100','00000200d7610700']
PARAM_NAMES=['kind','tm']
RUNATK_TYPE_RID=2548
RUNATK_TYPE_ROW='0301000093790000000000004503a8612d50'
FIELD=0x0400614E
FIELD_ROW='0100dbf2030001000000'
FIELD_SIG='0608'
CHILD=0x06004F9D
CHILD_SHA='58725b1757df7dd4bb511637f82b17f0ec95140b0a213f420cf88b318d04d065'
REF_DIGEST='e9d0ee20e1f8a635e56757aa09a1b5fd5349358ca7dbfc4a5cf3d32d938561ff'
CALLER_DIGEST='e48a1362b562dd41abab3f01e7ea30008538d8f7ac165edbac1edc490495f47d'

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''): h.update(c)
    return h.hexdigest()

def secs(pe):
    q=struct.unpack_from('<I',pe,0x3c)[0]
    if pe[q:q+4]!=b'PE\0\0': raise E('not PE')
    n=struct.unpack_from('<H',pe,q+6)[0]
    z=struct.unpack_from('<H',pe,q+20)[0]
    s=q+24+z
    out=[]
    for i in range(n):
        o=s+i*40
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
        out.append((va,max(vs,rs),rp))
    return out,q

def off(ss,r):
    for a,n,p in ss:
        if a<=r<a+n:return p+r-a
    raise E('RVA '+hex(r))

def meth(pe,ss,r):
    o=off(ss,r); b=pe[o]
    if b&3==2: return o+1,pe[o+1:o+1+(b>>2)]
    fs=struct.unpack_from('<H',pe,o)[0]; h=(fs>>12)*4; n=struct.unpack_from('<I',pe,o+4)[0]
    return o+h,pe[o+h:o+h+n]

def mdstreams(pe,ss,q):
    oo=q+24; dd=oo+(112 if struct.unpack_from('<H',pe,oo)[0]==0x20b else 96)
    cli=off(ss,struct.unpack_from('<I',pe,dd+112)[0])
    md=off(ss,struct.unpack_from('<I',pe,cli+8)[0])
    vl=struct.unpack_from('<I',pe,md+12)[0]
    p=(md+16+vl+3)&~3
    _,ns=struct.unpack_from('<HH',pe,p); p+=4
    st={}
    for _ in range(ns):
        a,n=struct.unpack_from('<II',pe,p); p+=8
        e=pe.index(b'\0',p); name=pe[p:e].decode(); p=(e+4)&~3
        st[name]=(md+a,n)
    t=st['#~'][0]; p=t+4
    _,_,hs,_=struct.unpack_from('<BBBB',pe,p); p+=4
    valid,_=struct.unpack_from('<QQ',pe,p); p+=16
    rows={}
    for i in range(64):
        if valid>>i&1:
            rows[i]=struct.unpack_from('<I',pe,p)[0]; p+=4
    return st,hs,rows,p

def rd(pe,p,n):
    return (struct.unpack_from('<I',pe,p)[0],p+4) if n==4 else (struct.unpack_from('<H',pe,p)[0],p+2)

def blob(pe,b,i):
    p=b+i; x=pe[p]
    if x<128:n=x;p+=1
    elif x<192:n=((x&63)<<8)|pe[p+1];p+=2
    else:n=((x&31)<<24)|(pe[p+1]<<16)|(pe[p+2]<<8)|pe[p+3];p+=4
    return pe[p:p+n]

def tables(pe,st,hs,rows,p):
    s=4 if hs&1 else 2; b=4 if hs&4 else 2
    def ix(t):return 4 if rows.get(t,0)>=65536 else 2
    def cx(ts,k):return 4 if max(rows.get(t,0) for t in ts)>=(1<<(16-k)) else 2
    z={0:2+s+3*(4 if hs&2 else 2),1:cx([0,26,35,1],2)+2*s,2:4+2*s+cx([2,1,27],2)+ix(4)+ix(6),3:ix(4),4:2+s+b,5:ix(6),6:8+s+b+ix(8),7:ix(8),8:4+s,9:ix(2)+cx([2,1,27],2),10:cx([2,1,26,6,27],3)+s+b,11:2+cx([4,8,23],2)+b,12:cx([6,4,1,2,8,9,10,0,14,23,20,17,26,27,32,35,38,39,40,42,44,43],5)+cx([6,10],3)+b,13:cx([4,8],1)+b,14:2+cx([2,6,32],2)+b,15:6+ix(2),16:4+ix(4),17:b}
    o={}; c=p
    for i in range(18):
        if i in rows:o[i]=c;c+=z[i]*rows[i]
    return s,b,ix,z,o

def s_at(pe,sb,i):
    p=sb+i
    return pe[p:pe.index(b'\0',p)].decode()

def owner_maps(pe,rows,s,ix,z,o,sb):
    ext=4 if max(rows.get(t,0) for t in (2,1,27))>=16384 else 2
    types=[]
    for rid in range(1,rows[2]+1):
        p=o[2]+(rid-1)*z[2]+4
        ni,p=rd(pe,p,s); nsi,p=rd(pe,p,s); p+=ext
        fl,p=rd(pe,p,ix(4)); ml,_=rd(pe,p,ix(6))
        types.append((s_at(pe,sb,ni),s_at(pe,sb,nsi),fl,ml))
    fm={}; mm={}
    for i,(name,ns,fl,ml) in enumerate(types):
        nfl=types[i+1][2] if i+1<len(types) else rows[4]+1
        nml=types[i+1][3] if i+1<len(types) else rows[6]+1
        for r in range(fl,nfl):fm[r]=(name,ns)
        for r in range(ml,nml):mm[r]=(name,ns)
    return fm,mm

def method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
    rid=tok&0xffffff
    p=o[6]+(rid-1)*z[6]
    raw=pe[p:p+z[6]]
    rva=struct.unpack_from('<I',raw)[0]
    impl=struct.unpack_from('<H',raw,4)[0]
    flags=struct.unpack_from('<H',raw,6)[0]
    q=p+8
    ni,q=rd(pe,q,s); si,q=rd(pe,q,b); plist,q=rd(pe,q,ix(8))
    start,body=meth(pe,ss,rva) if rva else (None,b'')
    return raw.hex(),rva,impl,flags,s_at(pe,sb,ni),blob(pe,bb,si).hex(),plist,owners.get(rid),start,body

def field(pe,s,b,z,o,sb,bb,fm,tok):
    rid=tok&0xffffff
    p=o[4]+(rid-1)*z[4]
    raw=pe[p:p+z[4]]
    q=p+2
    ni,q=rd(pe,q,s); si,_=rd(pe,q,b)
    return raw.hex(),fm.get(rid),s_at(pe,sb,ni),blob(pe,bb,si).hex()

def typedef(pe,rows,s,ix,z,o,sb,rid):
    extz=4 if max(rows.get(x,0) for x in (2,1,27))>=16384 else 2
    p=o[2]+(rid-1)*z[2]
    raw=pe[p:p+z[2]]
    q=p+4
    ni,q=rd(pe,q,s); nsi,q=rd(pe,q,s); ext,q=rd(pe,q,extz); fl,q=rd(pe,q,ix(4)); ml,q=rd(pe,q,ix(6))
    return raw.hex(),s_at(pe,sb,ni),s_at(pe,sb,nsi),ext,fl,ml

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[(b'\x28'+needle,'call'),(b'\x6f'+needle,'callvirt'),(b'\x73'+needle,'newobj'),(b'\x27'+needle,'jmp'),(b'\xfe\x06'+needle,'ldftn'),(b'\xfe\x07'+needle,'ldvirtftn')]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        md=method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        body=md[9]
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({'caller_type':md[7][0] if md[7] else None,'caller_namespace':md[7][1] if md[7] else None,'caller_method':md[4],'caller_token':f'0x{tok:08X}','caller_rva':f'0x{md[1]:08X}','caller_code_size':len(body),'caller_code_sha256':hashlib.sha256(body).hexdigest(),'call_il':f'0x{x:04X}','opcode':opname})
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=secs(pe); st,hs,rows,tp=mdstreams(pe,ss,q); s,b,ix,z,o=tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]; fm,owners=owner_maps(pe,rows,s,ix,z,o,sb)

    md=method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'SetAIAct_RunAtkToStunnedOpponent',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    if pe[off(ss,RVA)]!=HEADER: raise E('tiny header')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    nxt=method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)
    if nxt[6]!=plist+2: raise E('parameter range')
    for idx,(rowhex,pname) in enumerate(zip(PARAM_ROWS,PARAM_NAMES)):
        pp=o[8]+(plist+idx-1)*z[8]
        if pe[pp:pp+z[8]].hex()!=rowhex: raise E('parameter row '+str(idx+1))
        ni,_=rd(pe,pp+4,s)
        if s_at(pe,sb,ni)!=pname: raise E('parameter name '+str(idx+1))

    traw,tname,tns,_,_,_=typedef(pe,rows,s,ix,z,o,sb,RUNATK_TYPE_RID)
    if (traw,tname,tns)!=(RUNATK_TYPE_ROW,'RunAtkEnum',''): raise E('RunAtkEnum TypeDef')
    if field(pe,s,b,z,o,sb,bb,fm,FIELD)!=(FIELD_ROW,('PlayerController_AI',''),'aiActPrm',FIELD_SIG):
        raise E('aiActPrm field')

    if body[0:4]!=bytes([0x02,0x1f,0x0f,0x04]): raise E('SetAIAct argument loads')
    if body[4]!=0x28 or struct.unpack_from('<I',body,5)[0]!=CHILD: raise E('SetAIAct call')
    child=method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if child[4]!='SetAIAct' or child[7]!=('PlayerController_AI','') or len(child[9])!=102 or hashlib.sha256(child[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0043 child identity')
    if body[9:11]!=bytes([0x02,0x03]) or body[11]!=0x7d or struct.unpack_from('<I',body,12)[0]!=FIELD or body[16]!=0x2a:
        raise E('aiActPrm write/ret')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    expected=[{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x0119','opcode':'call'}]
    if rr!=expected: raise E('reference surface '+repr(rr))
    refd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if refd!=REF_DIGEST: raise E('reference digest '+refd)
    callers=sorted({x['caller_token'] for x in rr})
    cd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
    if cd!=CALLER_DIGEST: raise E('caller digest '+cd)
    return {'code_size':17,'code_sha256':SHA,'canonical_child_method_count':1,'direct_reference_count':1,'direct_caller_method_count':1,'reference_map_sha256':refd}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'PlayerController_AI.SetAIAct_RunAtkToStunnedOpponent':0,'PlayerController_AI.SetAIAct':0,'PlayerController_AI.Process_OpponentStands_Stun':0}
    with zipfile.ZipFile(path) as zf:
        if zf.testzip(): raise E('CRC')
        names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1: raise E('event trace count')
        bts=zf.read(names[0])
        if hashlib.sha256(bts).hexdigest()!=EVENT_SHA: raise E('event trace identity')
        for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
            if row['method'] in wanted:wanted[row['method']]+=1
    if any(wanted.values()): raise E('R6 boundary '+repr(wanted))
    return dict(wanted,promoted_as_evidence=False)

def main():
    a=argparse.ArgumentParser(); a.add_argument('--dll',required=True); a.add_argument('--r6',required=True); x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_RUN_ATK_TO_STUNNED_OPPONENT: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_SET_AI_ACT_RUN_ATK_TO_STUNNED_OPPONENT: FAIL')
        print(str(e)); return 1
if __name__=='__main__': raise SystemExit(main())
