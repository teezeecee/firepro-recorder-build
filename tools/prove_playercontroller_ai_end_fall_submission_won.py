#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06005025
RVA=0x002FF870
ROW='70f82f000000810013400a00db490000de3a'
SIG='200002'
FLAGS=0x0081
HEADER='13300300b4000000980c0011'
BODY=bytes.fromhex('7efa610004027b4a6100047bb15f00046f655000060a06282a00000a3a02000000162a027b4a6100047b486000043a10000000027b4a6100047b4b6000043968000000067b526000043a0b000000067b476000043946000000027b72610004163c0d000000021f3c7d72610004382800000002257b726100041759250b7d7261000407163d1100000002157d72610004021f207d18610004172a380700000002157d72610004380700000002157d72610004162a')
SHA='e43bed886326ec138725263c219956e6246d4a71aaaf3553d40b7c16ed2b7b89'

LOCAL_SIG_TOKEN=0x11000C98
LOCAL_SIG_ROW='61700200'
LOCAL_SIG_BLOB='070212a78808'
PLAYER_TYPE_RID=2530
PLAYER_TYPE_ROW='01001000fd480000000000005500565fa74e'

FIELDS={
0x040061FA:('PlayerMan','inst','160006220100cf380000','0612a818'),
0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
0x04005FB1:('Player','TargetPlIdx','060071e0030001000000','0608'),
0x04006048:('Player','isPinfallAtk','060064e7030008000000','0602'),
0x0400604B:('Player','isSubmissionAtk','06008ce7030008000000','0602'),
0x04006052:('Player','isLose','06000ee8030008000000','0602'),
0x04006047:('Player','isKO','06005fe7030008000000','0602'),
0x04006172:('PlayerController_AI','endFallTimer','0100e1f4030001000000','0608'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c')
}
ACCESS=[
(0x0000,'ldsfld',0x040061FA),
(0x0006,'ldfld',0x0400614A),
(0x000B,'ldfld',0x04005FB1),
(0x0024,'ldfld',0x0400614A),
(0x0029,'ldfld',0x04006048),
(0x0034,'ldfld',0x0400614A),
(0x0039,'ldfld',0x0400604B),
(0x0044,'ldfld',0x04006052),
(0x004F,'ldfld',0x04006047),
(0x005A,'ldfld',0x04006172),
(0x0068,'stfld',0x04006172),
(0x0074,'ldfld',0x04006172),
(0x007D,'stfld',0x04006172),
(0x008B,'stfld',0x04006172),
(0x0093,'stfld',0x04006118),
(0x00A1,'stfld',0x04006172),
(0x00AD,'stfld',0x04006172)
]
FIELD_ACCESS_DIGEST='16ca98963995d1904ac34e07dc8b14f1d465aa79853589378e9bef4efec59722'

CHILD=0x06005065
CHILD_SHA='32cbd360156f7bbbf97ed096e6afa8d4e7e4e500ff3d37179f32aecfafcf05d8'
EXT=0x0A00002A
EXT_ROW='d100000085510600e9490000'
EXT_SIG='0001021269'
TYPE_REF_RID=26
TYPE_REF_ROW='06001cb8000080a60000'

AFTER_MATCH=0x06005021
AFTER_MATCH_RVA=0x002FF5C0
AFTER_MATCH_SIZE=324
AFTER_MATCH_SHA='d628435e41eb6e76aa71c35f069f841c85bcf149e7c08317b910cff04add458b'
AFTER_MATCH_CALL_IL=0x003E

UPDATE=0x0600502B
UPDATE_RVA=0x002FFC68
UPDATE_SIZE=984
UPDATE_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'
UPDATE_CALL_IL=0x00AE

REF_DIGEST='2071fc6d9b8540f9a1bbbef6ce5c63b0f0718d2f3224e1038a1ab22ea170ee9f'
CALLER_DIGEST='af1a57e5dc72e932feaa7fcf00d969af285afd85d7d99e51151c90bf00511fa8'

class E(RuntimeError):
    pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''):
            h.update(c)
    return h.hexdigest()

def compressed_uint(blob,pos):
    x=blob[pos]
    if x<0x80:
        return x,pos+1
    if x<0xC0:
        return ((x&0x3f)<<8)|blob[pos+1],pos+2
    return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4

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
        raw,rva,impl,flags,name,sig,plist,owner,start,body=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
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

    raw,rva,impl,flags,name,sig,plist,owner,start,body=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'EndFallSubmission_Won',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER:
        raise E('fat header')
    if struct.unpack_from('<H',pe,ho+2)[0]!=3 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN:
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA:
        raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    sraw=pe[sp:sp+z[17]].hex()
    si,_=base.rd(pe,sp,b)
    lblob=base.blob(pe,bb,si)
    if sraw!=LOCAL_SIG_ROW or lblob.hex()!=LOCAL_SIG_BLOB:
        raise E('local signature')
    if lblob[:3]!=bytes([0x07,0x02,0x12]):
        raise E('local signature prefix')
    coded,pos=compressed_uint(lblob,3)
    if (coded&3)!=0 or (coded>>2)!=PLAYER_TYPE_RID or lblob[pos:]!=bytes([0x08]):
        raise E('local types')
    traw,tname,tns,textends,tfl,tml=drop.typedef(pe,rows,s,ix,z,o,sb,PLAYER_TYPE_RID)
    if (traw,tname,tns)!=(PLAYER_TYPE_ROW,'Player',''):
        raise E('Player local TypeDef')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg):
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

    got_calls=drop.calls(body)
    if got_calls!=[(0x0010,0x6f,CHILD),(0x0017,0x28,EXT)]:
        raise E('call surface '+repr(got_calls))
    child=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if child[4]!='GetPlObj' or child[7]!=('PlayerMan','') or len(child[9])!=25 or hashlib.sha256(child[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0109 child identity')

    eraw,eparent,ename,esig=drop.member(pe,rows,s,b,z,o,sb,bb,EXT)
    if (eraw,eparent,ename,esig)!=(EXT_ROW,0xD1,'op_Implicit',EXT_SIG):
        raise E('external MemberRef')
    rraw,rscope,rname,rns=drop.typeref(pe,s,z,o,sb,TYPE_REF_RID)
    if (rraw,rname,rns)!=(TYPE_REF_ROW,'Object','UnityEngine'):
        raise E('UnityEngine.Object TypeRef')

    branches=[
        (0x001C,0x3A,0x0023),
        (0x002E,0x3A,0x0043),
        (0x003E,0x39,0x00AB),
        (0x0049,0x3A,0x0059),
        (0x0054,0x39,0x009F),
        (0x0060,0x3C,0x0072),
        (0x006D,0x38,0x009A),
        (0x0084,0x3D,0x009A),
        (0x009A,0x38,0x00A6),
        (0x00A6,0x38,0x00B2)
    ]
    for il,op,target in branches:
        if body[il]!=op or drop.target4(body,il)!=target:
            raise E('branch '+hex(il))

    if not (body[0x0065]==0x02 and body[0x0066:0x0068]==bytes([0x1f,60]) and body[0x0068]==0x7d):
        raise E('timer raw 60')
    if not (body[0x0079]==0x17 and body[0x007A]==0x59 and body[0x007B]==0x25 and body[0x007C]==0x0B and body[0x007D]==0x7D):
        raise E('timer decrement')
    if not (body[0x0089]==0x02 and body[0x008A]==0x15 and body[0x008B]==0x7D):
        raise E('completion timer raw -1')
    if not (body[0x0090]==0x02 and body[0x0091:0x0093]==bytes([0x1f,32]) and body[0x0093]==0x7D):
        raise E('padPush raw 32')
    if not (body[0x009F]==0x02 and body[0x00A0]==0x15 and body[0x00A1]==0x7D):
        raise E('target-fail timer raw -1')
    if not (body[0x00AB]==0x02 and body[0x00AC]==0x15 and body[0x00AD]==0x7D):
        raise E('action-fail timer raw -1')
    if not (body[0x0021]==0x16 and body[0x0022]==0x2A):
        raise E('null false return')
    if not (body[0x0098]==0x17 and body[0x0099]==0x2A):
        raise E('true return')
    if not (body[0x00B2]==0x16 and body[0x00B3]==0x2A):
        raise E('shared false return')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    expected=[
      {
        'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_AfterMatchEnd',
        'caller_token':'0x06005021','caller_rva':'0x002FF5C0','caller_code_size':324,
        'caller_code_sha256':AFTER_MATCH_SHA,'call_il':'0x003E','opcode':'call'
      },
      {
        'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Update',
        'caller_token':'0x0600502B','caller_rva':'0x002FFC68','caller_code_size':984,
        'caller_code_sha256':UPDATE_SHA,'call_il':'0x00AE','opcode':'call'
      }
    ]
    if rr!=expected:
        raise E('direct reference surface '+repr(rr))
    rdigest=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rdigest!=REF_DIGEST:
        raise E('reference digest '+rdigest)
    cdigest=hashlib.sha256(('0x06005021\n0x0600502B\n').encode()).hexdigest()
    if cdigest!=CALLER_DIGEST:
        raise E('caller digest '+cdigest)

    after=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,AFTER_MATCH)
    if after[1]!=AFTER_MATCH_RVA or after[4]!='Process_AfterMatchEnd' or after[7]!=('PlayerController_AI','') or len(after[9])!=AFTER_MATCH_SIZE or hashlib.sha256(after[9]).hexdigest()!=AFTER_MATCH_SHA:
        raise E('Process_AfterMatchEnd identity')
    if after[9][AFTER_MATCH_CALL_IL]!=0x28 or struct.unpack_from('<I',after[9],AFTER_MATCH_CALL_IL+1)[0]!=T:
        raise E('Process_AfterMatchEnd callsite')

    update=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,UPDATE)
    if update[1]!=UPDATE_RVA or update[4]!='Update' or update[7]!=('PlayerController_AI','') or len(update[9])!=UPDATE_SIZE or hashlib.sha256(update[9]).hexdigest()!=UPDATE_SHA:
        raise E('AI Update identity')
    if update[9][UPDATE_CALL_IL]!=0x28 or struct.unpack_from('<I',update[9],UPDATE_CALL_IL+1)[0]!=T:
        raise E('AI Update callsite')

    return {
        'code_size':180,
        'code_sha256':SHA,
        'canonical_internal_methoddef_reference_count':1,
        'external_memberref_count':1,
        'direct_reference_count':2,
        'direct_caller_method_count':2,
        'reference_map_sha256':rdigest
    }

def verify_r6(path):
    if sh(path)!=R6_SHA:
        raise E('R6 identity')
    wanted={
        'PlayerController_AI.EndFallSubmission_Won':0,
        'PlayerMan.GetPlObj':0,
        'PlayerController_AI.Process_AfterMatchEnd':0,
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
        print('PROVE_PLAYERCONTROLLER_AI_END_FALL_SUBMISSION_WON: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_END_FALL_SUBMISSION_WON: FAIL')
        print(str(e))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
