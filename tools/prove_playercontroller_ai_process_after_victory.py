#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_weapon_update_falling as base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06005020
RVA=0x002FF53C
ROW='3cf52f0000008100ac3f0a00db490000de3a'
SIG='200002'
FLAGS=0x0081
HEADER='13300200770000003f110011'
BODY=bytes.fromhex('027b666100043902000000162a7e6c5700047b535700043a02000000162a027b4a6100047bb75f0004193e02000000162a7eff5600047b00570004027b4a6100047ba65f00049a7bcf5600040a0639070000000617401b0000000220004000007d1861000402167d1761000402177d66610004172a162a')
SHA='5334c091183b118519531eb8a6518584bff6b89ddf64bb343899315321cd59dc'

LOCAL_SIG_TOKEN=0x1100113F
LOCAL_SIG_ROW='41d30200'
LOCAL_SIG_BLOB='070111a39c'
LOCAL_TYPE_RID=2279
LOCAL_TYPE_ROW='01010000da6a0000000000004503ad56d048'

FIELDS={
0x04006166:('PlayerController_AI','doneVictoryPerformance','010030f4030008000000','0602'),
0x0400576C:('MatchMain','inst','16000622010079320000','0612a3c8'),
0x04005753:('MatchMain','isMatchEnd','0600f788030008000000','0602'),
0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
0x04005FB7:('Player','State','06006e000000da370000','0611a828'),
0x040056FF:('MatchEvaluation','inst','1600062201004c320000','0612a3bc'),
0x04005700:('MatchEvaluation','PlResult','06007a84030051320000','061d12a3b0'),
0x04005FA6:('Player','PlIdx','0600bdb2030001000000','0608'),
0x040056CF:('PlayerMatchResult','resultPosition','06009682030028320000','0611a39c'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c')
}
ACCESS=[
(0x0001,'ldfld',0x04006166),
(0x000D,'ldsfld',0x0400576C),
(0x0012,'ldfld',0x04005753),
(0x001F,'ldfld',0x0400614A),
(0x0024,'ldfld',0x04005FB7),
(0x0031,'ldsfld',0x040056FF),
(0x0036,'ldfld',0x04005700),
(0x003C,'ldfld',0x0400614A),
(0x0041,'ldfld',0x04005FA6),
(0x0047,'ldfld',0x040056CF),
(0x0060,'stfld',0x04006118),
(0x0067,'stfld',0x04006117),
(0x006E,'stfld',0x04006166)
]
FIELD_ACCESS_DIGEST='d15eb9ead3cef5447ef970087f12de574c66c52c8b64285d8e2b51311962c92f'

PARENT=0x0600502B
PARENT_RVA=0x002FFC68
PARENT_SIZE=984
PARENT_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'
PARENT_CALL_IL=0x028C

REF_DIGEST='2cca62a08c4daa6d8de2163b0d991ec736ecc55decd5e89746b5859603cc0dc2'
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

def compressed_uint(blob,pos):
    x=blob[pos]
    if x<0x80:
        return x,pos+1
    if x<0xC0:
        return ((x&0x3f)<<8)|blob[pos+1],pos+2
    return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4

def call_operands(body):
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
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_AfterVictory',SIG,('PlayerController_AI','')):
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
    lblob=base.blob(pe,bb,si)
    if sraw!=LOCAL_SIG_ROW or lblob.hex()!=LOCAL_SIG_BLOB:
        raise E('local signature')
    if lblob[:3]!=bytes([0x07,0x01,0x11]):
        raise E('local signature prefix')
    coded,end=compressed_uint(lblob,3)
    if end!=len(lblob) or (coded&3)!=0 or (coded>>2)!=LOCAL_TYPE_RID:
        raise E('local ResultPosition coded token')
    traw,tname,tns,textends,tfl,tml=typedef(pe,rows,s,ix,z,o,sb,LOCAL_TYPE_RID)
    if (traw,tname,tns)!=(LOCAL_TYPE_ROW,'ResultPosition',''):
        raise E('local ResultPosition TypeDef')

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

    if call_operands(body)!=[]:
        raise E('unexpected call surface '+repr(call_operands(body)))

    if body[0x0006]!=0x39 or target4(body,0x0006)!=0x000D:
        raise E('doneVictoryPerformance branch')
    if body[0x0017]!=0x3A or target4(body,0x0017)!=0x001E:
        raise E('isMatchEnd branch')
    if not (body[0x0029]==0x19 and body[0x002A]==0x3E and target4(body,0x002A)==0x0031):
        raise E('State <= 3 branch')
    if body[0x0046]!=0x9A:
        raise E('PlResult ldelem.ref')
    if body[0x004D]!=0x06 or body[0x004E]!=0x39 or target4(body,0x004E)!=0x005A:
        raise E('ResultPosition raw 0 branch')
    if not (body[0x0053]==0x06 and body[0x0054]==0x17 and body[0x0055]==0x40 and target4(body,0x0055)==0x0075):
        raise E('ResultPosition raw 1 branch')

    if not (body[0x005A]==0x02 and body[0x005B]==0x20 and struct.unpack_from('<i',body,0x005C)[0]==16384 and body[0x0060]==0x7D):
        raise E('padPush raw 16384 write')
    if not (body[0x0065]==0x02 and body[0x0066]==0x16 and body[0x0067]==0x7D):
        raise E('padOn raw 0 write')
    if not (body[0x006C]==0x02 and body[0x006D]==0x17 and body[0x006E]==0x7D):
        raise E('doneVictoryPerformance true write')

    for ret_il in (0x000C,0x001D,0x0030,0x0076):
        if body[ret_il-1]!=0x16 or body[ret_il]!=0x2A:
            raise E('false return '+hex(ret_il))
    if body[0x0073]!=0x17 or body[0x0074]!=0x2A:
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
        'call_il':'0x028C',
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
        'code_size':119,
        'code_sha256':SHA,
        'internal_call_count':0,
        'direct_reference_count':1,
        'direct_caller_method_count':1,
        'reference_map_sha256':rdigest,
        'parent':'PlayerController_AI.Update'
    }

def verify_r6(path):
    if sh(path)!=R6_SHA:
        raise E('R6 identity')
    wanted={
        'PlayerController_AI.Process_AfterVictory':0,
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
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_AFTER_VICTORY: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_AFTER_VICTORY: FAIL')
        print(str(e))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
