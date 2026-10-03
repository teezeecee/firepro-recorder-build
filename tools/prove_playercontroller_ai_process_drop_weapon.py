#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06005022
RVA=0x002FF710
ROW='10f72f0000008100d73f0a00db490000de3a'
SIG='200002'
FLAGS=0x0081
HEADER='133002006d00000069090011'
BODY=bytes.fromhex('027b4a6100047b0b600004163c02000000162a7edc6200046fb65000060a06282a00000a3a02000000162a067ba4620004027b4a6100047ba65f00043b02000000162a067b9d6200041f0e3b02000000162a067bcc6200041a3c02000000162a0220800000007d18610004172a')
SHA='b7c63a31c3fd694f21dc16ae22caf91866d1eb98336000f37e5b763c71d672dd'

LOCAL_SIG_TOKEN=0x11000969
LOCAL_SIG_ROW='0f330200'
LOCAL_SIG_BLOB='070112a838'
LOCAL_TYPE_RID=2574
LOCAL_TYPE_ROW='010010005f7b000000000000550086627650'

FIELDS={
0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
0x0400600B:('Player','weaponIdx','06009ee4030001000000','0608'),
0x040062DC:('RefereeMan','inst','1600062201000c390000','0612a83c'),
0x040062A4:('Referee','TargetPlIdx','060071e0030001000000','0608'),
0x04005FA6:('Player','PlIdx','0600bdb2030001000000','0608'),
0x0400629D:('Referee','State','06006e00000007390000','0611a834'),
0x040062CC:('Referee','RefeCount','0600cb01040001000000','0608'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c')
}
ACCESS=[
(0x0001,'ldfld',0x0400614A),
(0x0006,'ldfld',0x0400600B),
(0x0013,'ldsfld',0x040062DC),
(0x002C,'ldfld',0x040062A4),
(0x0032,'ldfld',0x0400614A),
(0x0037,'ldfld',0x04005FA6),
(0x0044,'ldfld',0x0400629D),
(0x0053,'ldfld',0x040062CC),
(0x0066,'stfld',0x04006118)
]
FIELD_ACCESS_DIGEST='ca0ae7487f9d008d649907116730fbd536f7bed894c97ed14f785e06f8eb6fb2'

CHILD=0x060050B6
CHILD_SHA='aa2a417db5ba1940541d91f5a98fe26ec59230af147fdb4dd2e768ca0dad1e4d'
EXT=0x0A00002A
EXT_ROW='d100000085510600e9490000'
EXT_SIG='0001021269'
TYPE_REF_RID=26
TYPE_REF_ROW='06001cb8000080a60000'

PARENT=0x0600502B
PARENT_RVA=0x002FFC68
PARENT_SIZE=984
PARENT_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'
PARENT_CALL_IL=0x01B5

REF_DIGEST='44fe025ddce4ea8911d33dbcb9a21828339ec328f0f8917b0fc631c39b6f54f6'
CALLER_DIGEST='8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63'

class E(RuntimeError):
    pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''):
            h.update(c)
    return h.hexdigest()

def method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok):
    rid=tok&0xffffff
    p=o[6]+(rid-1)*z[6]
    raw=pe[p:p+z[6]]
    rva=struct.unpack_from('<I',raw)[0]
    impl=struct.unpack_from('<H',raw,4)[0]
    flags=struct.unpack_from('<H',raw,6)[0]
    q=p+8
    ni,q=base.rd(pe,q,s)
    si,q=base.rd(pe,q,b)
    plist,q=base.rd(pe,q,ix(8))
    start,body=base.meth(pe,ss,rva) if rva else (None,b'')
    return raw.hex(),rva,impl,flags,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex(),plist,owners.get(rid),start,body

def field(pe,s,b,z,o,sb,bb,fm,tok):
    rid=tok&0xffffff
    p=o[4]+(rid-1)*z[4]
    raw=pe[p:p+z[4]]
    q=p+2
    ni,q=base.rd(pe,q,s)
    si,_=base.rd(pe,q,b)
    return raw.hex(),fm.get(rid),base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()

def member(pe,rows,s,b,z,o,sb,bb,tok):
    rid=tok&0xffffff
    psz=4 if max(rows.get(t,0) for t in (2,1,26,6,27))>=(1<<(16-3)) else 2
    p=o[10]+(rid-1)*z[10]
    raw=pe[p:p+z[10]]
    parent_raw=int.from_bytes(pe[p:p+psz],'little')
    q=p+psz
    ni,q=base.rd(pe,q,s)
    si,_=base.rd(pe,q,b)
    return raw.hex(),parent_raw,base.s_at(pe,sb,ni),base.blob(pe,bb,si).hex()

def typeref(pe,s,z,o,sb,rid):
    p=o[1]+(rid-1)*z[1]
    raw=pe[p:p+z[1]]
    scope_size=z[1]-2*s
    q=p
    scope,q=base.rd(pe,q,scope_size)
    ni,q=base.rd(pe,q,s)
    nsi,q=base.rd(pe,q,s)
    return raw.hex(),scope,base.s_at(pe,sb,ni),base.s_at(pe,sb,nsi)

def typedef(pe,rows,s,ix,z,o,sb,rid):
    extz=4 if max(rows.get(x,0) for x in (2,1,27))>=16384 else 2
    p=o[2]+(rid-1)*z[2]
    raw=pe[p:p+z[2]]
    q=p+4
    ni,q=base.rd(pe,q,s)
    nsi,q=base.rd(pe,q,s)
    ext,q=base.rd(pe,q,extz)
    fl,q=base.rd(pe,q,ix(4))
    ml,q=base.rd(pe,q,ix(6))
    return raw.hex(),base.s_at(pe,sb,ni),base.s_at(pe,sb,nsi),ext,fl,ml

def calls(body):
    out=[]
    for i in range(len(body)-4):
        if body[i] in (0x28,0x6f,0x73,0x27):
            tok=struct.unpack_from('<I',body,i+1)[0]
            if (tok>>24) in (0x06,0x0A):
                out.append((i,body[i],tok))
        elif body[i]==0xfe and i+5<len(body) and body[i+1] in (0x06,0x07):
            tok=struct.unpack_from('<I',body,i+2)[0]
            if (tok>>24) in (0x06,0x0A):
                out.append((i,0x100|body[i+1],tok))
    return out

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[
        (bytes([0x28])+needle,'call'),
        (bytes([0x6f])+needle,'callvirt'),
        (bytes([0x73])+needle,'newobj'),
        (bytes([0x27])+needle,'jmp'),
        (bytes([0xfe,0x06])+needle,'ldftn'),
        (bytes([0xfe,0x07])+needle,'ldvirtftn')
    ]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        raw,rva,impl,flags,name,sig,plist,owner,start,body=method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if not body:
            continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0:
                    break
                out.append({
                    'caller_type':owner[0] if owner else None,
                    'caller_namespace':owner[1] if owner else None,
                    'caller_method':name,
                    'caller_token':f'0x{tok:08X}',
                    'caller_rva':f'0x{rva:08X}',
                    'caller_code_size':len(body),
                    'caller_code_sha256':hashlib.sha256(body).hexdigest(),
                    'call_il':f'0x{x:04X}',
                    'opcode':opname
                })
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def target4(body,il):
    return il+5+struct.unpack_from('<i',body,il+1)[0]

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA:
        raise E('DLL identity')

    ss,q=base.secs(pe)
    st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]
    bb=st['#Blob'][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    raw,rva,impl,flags,name,sig,plist,owner,start,body=method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_DropWeapon',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER:
        raise E('fat header')
    if struct.unpack_from('<H',pe,ho+2)[0]!=2 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN:
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:
        raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    sraw=pe[sp:sp+z[17]].hex()
    si,_=base.rd(pe,sp,b)
    if sraw!=LOCAL_SIG_ROW or base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB:
        raise E('local signature')
    traw,tname,tns,textends,tfl,tml=typedef(pe,rows,s,ix,z,o,sb,LOCAL_TYPE_RID)
    if (traw,tname,tns)!=(LOCAL_TYPE_ROW,'Referee',''):
        raise E('local Referee TypeDef')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):
            raise E('field '+hex(tok))

    opbytes={'ldfld':0x7b,'ldsfld':0x7e,'stfld':0x7d}
    amap=[]
    for il,opname,tok in ACCESS:
        op=opbytes[opname]
        if body[il]!=op or struct.unpack_from('<I',body,il+1)[0]!=tok:
            raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
    d=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=FIELD_ACCESS_DIGEST:
        raise E('field access digest '+d)

    got_calls=calls(body)
    if got_calls!=[(0x0018,0x6f,CHILD),(0x001f,0x28,EXT)]:
        raise E('call surface '+repr(got_calls))
    child=method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if child[4]!='GetRefereeObj' or child[7]!=('RefereeMan','') or len(child[9])!=9 or hashlib.sha256(child[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0065 child identity')

    eraw,eparent,ename,esig=member(pe,rows,s,b,z,o,sb,bb,EXT)
    if (eraw,eparent,ename,esig)!=(EXT_ROW,0xD1,'op_Implicit',EXT_SIG):
        raise E('external MemberRef')
    rraw,rscope,rname,rns=typeref(pe,s,z,o,sb,TYPE_REF_RID)
    if (rraw,rname,rns)!=(TYPE_REF_ROW,'Object','UnityEngine'):
        raise E('UnityEngine.Object TypeRef')

    if not (body[0x000B]==0x16 and body[0x000C]==0x3c and target4(body,0x000C)==0x0013):
        raise E('weaponIdx gate')
    if not (body[0x0024]==0x3a and target4(body,0x0024)==0x002B):
        raise E('Object implicit gate')
    if not (body[0x003C]==0x3b and target4(body,0x003C)==0x0043):
        raise E('TargetPlIdx gate')
    if not (body[0x0049:0x004B]==bytes([0x1f,14]) and body[0x004B]==0x3b and target4(body,0x004B)==0x0052):
        raise E('State 14 gate')
    if not (body[0x0058]==0x1a and body[0x0059]==0x3c and target4(body,0x0059)==0x0060):
        raise E('RefeCount 4 gate')
    if not (body[0x0061]==0x20 and struct.unpack_from('<i',body,0x0062)[0]==128 and body[0x0066]==0x7d):
        raise E('padPush 128 write')
    for ret_il in (0x0012,0x002A,0x0042,0x0051,0x005F):
        if body[ret_il-1]!=0x16 or body[ret_il]!=0x2A:
            raise E('false return '+hex(ret_il))
    if body[0x006B]!=0x17 or body[0x006C]!=0x2A:
        raise E('true return')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    expected=[{
        'caller_type':'PlayerController_AI',
        'caller_namespace':'',
        'caller_method':'Update',
        'caller_token':'0x0600502B',
        'caller_rva':'0x002FFC68',
        'caller_code_size':984,
        'caller_code_sha256':PARENT_SHA,
        'call_il':'0x01B5',
        'opcode':'call'
    }]
    if rr!=expected:
        raise E('direct reference surface '+repr(rr))
    rdigest=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rdigest!=REF_DIGEST:
        raise E('reference digest '+rdigest)
    cdigest=hashlib.sha256(('0x0600502B\n').encode()).hexdigest()
    if cdigest!=CALLER_DIGEST:
        raise E('caller digest '+cdigest)

    parent=method(pe,ss,s,b,ix,z,o,sb,bb,owners,PARENT)
    if parent[1]!=PARENT_RVA or parent[4]!='Update' or parent[7]!=('PlayerController_AI','') or len(parent[9])!=PARENT_SIZE or hashlib.sha256(parent[9]).hexdigest()!=PARENT_SHA:
        raise E('AI Update identity')
    if parent[9][PARENT_CALL_IL]!=0x28 or struct.unpack_from('<I',parent[9],PARENT_CALL_IL+1)[0]!=T:
        raise E('AI Update callsite')

    return {
        'code_size':109,
        'code_sha256':SHA,
        'canonical_internal_methoddef_reference_count':1,
        'external_memberref_count':1,
        'direct_reference_count':1,
        'direct_caller_method_count':1,
        'reference_map_sha256':rdigest,
        'parent':'PlayerController_AI.Update'
    }

def verify_r6(path):
    if sh(path)!=R6_SHA:
        raise E('R6 identity')
    wanted={
        'PlayerController_AI.Process_DropWeapon':0,
        'RefereeMan.GetRefereeObj':0,
        'PlayerController_AI.Update':0
    }
    with zipfile.ZipFile(path) as zf:
        if zf.testzip():
            raise E('CRC')
        names=[n for n in zf.namelist() if Path(n).name=='event_trace.tsv']
        if len(names)!=1:
            raise E('event trace count')
        bts=zf.read(names[0])
        if hashlib.sha256(bts).hexdigest()!=EVENT_SHA:
            raise E('event trace identity')
        for row in csv.DictReader(io.StringIO(bts.decode('utf-8-sig')),delimiter='\t'):
            if row['method'] in wanted:
                wanted[row['method']]+=1
    if any(wanted.values()):
        raise E('R6 boundary '+repr(wanted))
    return dict(wanted,promoted_as_evidence=False)

def main():
    a=argparse.ArgumentParser()
    a.add_argument('--dll',required=True)
    a.add_argument('--r6',required=True)
    x=a.parse_args()
    try:
        print(json.dumps({'dll':verify_dll(x.dll),'r6':verify_r6(x.r6)},indent=2,sort_keys=True))
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_DROP_WEAPON: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_DROP_WEAPON: FAIL')
        print(str(e))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
