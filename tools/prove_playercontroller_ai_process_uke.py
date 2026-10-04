#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base

DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004FE6
RVA=0x002FA42C
ROW='2ca42f0000008100eb3a0a005c480000d43a'
SIG='200001'
FLAGS=0x0081
HEADER='13300300c700000014110011'
BODY=bytes.fromhex('027b4a6100047bb35f00047baa1000040a160b027b4a6100047bb75f00041f113b12000000027b4a6100047bb75f00041f124007000000170b3825000000027b4a6100047bb75f00041f164013000000027b1861000420f00200005f3a02000000170b073a010000002a027b4a6100047bbf5f0004289b4f00060c160d083a0c000000067b1d0d00040d381a0000000817400c000000067b1e0d00040d3807000000067b1f0d00040d092855490006391200000002257b176100042000010000607d176100042a')
SHA='5a01db6954a400136e9050584744d4bedd5962586fa1d731211e9c0f313d9295'

LOCAL_SIG_TOKEN=0x11001114
LOCAL_SIG_ROW='1ed00200'
LOCAL_SIG_BLOB='07041286300211a7c408'
AIPARAM_TYPE_RID=396
AIPARAM_TYPE_ROW='012010005b140000000000000903fa0c4110'
DAMAGE_TYPE_RID=2545
DAMAGE_TYPE_ROW='030100005e7900000000000045039a612d50'

FIELDS={
0x0400614A:('PlayerController_AI','PlObj','0100b7f203005e190000','0612a788'),
0x04005FB3:('Player','WresParam','060088e003008f0b0000','061287ac'),
0x040010AA:('WrestlerParam','aiParam','0600e95b0100810d0000','06128630'),
0x04005FB7:('Player','State','06006e000000da370000','0611a828'),
0x04006118:('PlayerController','padPush','0600f66a0100440c0000','0611904c'),
0x04005FBF:('Player','HP','0600b67f010014000000','060c'),
0x04000D1D:('AIParam','breakFall_LDmg','06006f3c010001000000','0608'),
0x04000D1E:('AIParam','breakFall_MDmg','06007e3c010001000000','0608'),
0x04000D1F:('AIParam','breakFall_HDmg','06008d3c010001000000','0608'),
0x04006117:('PlayerController','padOn','0600f71f0200440c0000','0611904c')
}
ACCESS=[
(0x0001,'ldfld',0x0400614A),
(0x0006,'ldfld',0x04005FB3),
(0x000B,'ldfld',0x040010AA),
(0x0014,'ldfld',0x0400614A),
(0x0019,'ldfld',0x04005FB7),
(0x0026,'ldfld',0x0400614A),
(0x002B,'ldfld',0x04005FB7),
(0x003F,'ldfld',0x0400614A),
(0x0044,'ldfld',0x04005FB7),
(0x0051,'ldfld',0x04006118),
(0x006B,'ldfld',0x0400614A),
(0x0070,'ldfld',0x04005FBF),
(0x0084,'ldfld',0x04000D1D),
(0x0097,'ldfld',0x04000D1E),
(0x00A3,'ldfld',0x04000D1F),
(0x00B6,'ldfld',0x04006117),
(0x00C1,'stfld',0x04006117)
]
FIELD_ACCESS_DIGEST='64b1da5a1b8d813d736515974bb69f061a6358651790a8b9bce917ce86dd8cc5'

DAMAGE=0x06004F9B
DAMAGE_SHA='9c943eda48fd9f9c76271366324f22095426c06b0eecbb77d37e0cc945dde6c3'
RATE=0x06004955
RATE_SHA='6899b69e72e4f0b5853a85c1cb3796e28442d2abbd4ca2378d72dd59ce7bba58'

PARENT=0x0600502B
PARENT_RVA=0x002FFC68
PARENT_SIZE=984
PARENT_SHA='6cea6fc2585177a22c56446c0be26152eed5061fdb0239837f775cad0c2be6d9'
PARENT_CALL_IL=0x03D2

REF_DIGEST='75d6657386ea1078b0385ae51f25352a4e249b8962945b55cb7c3c4d2e3cad78'
CALLER_DIGEST='8ac1dfd1d928208b427b89fc6c0c23e9bda7b0f8a86a44a10454754a87056c63'

class E(RuntimeError): pass

def sh(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for c in iter(lambda:f.read(1048576),b''):
            h.update(c)
    return h.hexdigest()

def compressed_uint(blob,pos):
    x=blob[pos]
    if x<0x80: return x,pos+1
    if x<0xC0: return ((x&0x3f)<<8)|blob[pos+1],pos+2
    return ((x&0x1f)<<24)|(blob[pos+1]<<16)|(blob[pos+2]<<8)|blob[pos+3],pos+4

def refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows):
    needle=struct.pack('<I',T)
    pats=[
        (bytes([0x28])+needle,'call'),(bytes([0x6f])+needle,'callvirt'),
        (bytes([0x73])+needle,'newobj'),(bytes([0x27])+needle,'jmp'),
        (bytes([0xfe,0x06])+needle,'ldftn'),(bytes([0xfe,0x07])+needle,'ldvirtftn')
    ]
    out=[]
    for rid in range(1,rows[6]+1):
        tok=0x06000000|rid
        raw,rva,impl,flags,name,sig,plist,owner,start,body=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,tok)
        if not body: continue
        for pat,opname in pats:
            pos=0
            while True:
                x=body.find(pat,pos)
                if x<0: break
                out.append({
                    'caller_type':owner[0] if owner else None,
                    'caller_namespace':owner[1] if owner else None,
                    'caller_method':name,'caller_token':f'0x{tok:08X}',
                    'caller_rva':f'0x{rva:08X}','caller_code_size':len(body),
                    'caller_code_sha256':hashlib.sha256(body).hexdigest(),
                    'call_il':f'0x{x:04X}','opcode':opname
                })
                pos=x+1
    out.sort(key=lambda x:(int(x['caller_token'],16),int(x['call_il'],16),x['opcode']))
    return out

def verify_dll(path):
    pe=Path(path).read_bytes()
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe); st,hs,rows,tp=base.mdstreams(pe,ss,q); s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]; fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    raw,rva,impl,flags,name,sig,plist,owner,start,body=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'Process_Uke',SIG,('PlayerController_AI','')): raise E('method metadata')
    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    if struct.unpack_from('<H',pe,ho+2)[0]!=3 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN: raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    sraw=pe[sp:sp+z[17]].hex(); si,_=base.rd(pe,sp,b); lblob=base.blob(pe,bb,si)
    if sraw!=LOCAL_SIG_ROW or lblob.hex()!=LOCAL_SIG_BLOB: raise E('local signature')
    if lblob[:3]!=bytes([0x07,0x04,0x12]): raise E('local signature prefix')
    coded,pos=compressed_uint(lblob,3)
    if (coded&3)!=0 or (coded>>2)!=AIPARAM_TYPE_RID or lblob[pos]!=0x02 or lblob[pos+1]!=0x11: raise E('local0/local1')
    coded2,pos2=compressed_uint(lblob,pos+2)
    if (coded2&3)!=0 or (coded2>>2)!=DAMAGE_TYPE_RID or lblob[pos2:]!=bytes([0x08]): raise E('local2/local3')
    if drop.typedef(pe,rows,s,ix,z,o,sb,AIPARAM_TYPE_RID)[:3]!=(AIPARAM_TYPE_ROW,'AIParam',''): raise E('AIParam TypeDef')
    if drop.typedef(pe,rows,s,ix,z,o,sb,DAMAGE_TYPE_RID)[:3]!=(DAMAGE_TYPE_ROW,'DamageLevelEnum_LMH',''): raise E('DamageLevelEnum_LMH TypeDef')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg): raise E('field '+hex(tok))

    amap=[]; opbytes={'ldfld':0x7b,'stfld':0x7d}
    for il,opname,tok in ACCESS:
        if body[il]!=opbytes[opname] or struct.unpack_from('<I',body,il+1)[0]!=tok: raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
    d=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if d!=FIELD_ACCESS_DIGEST: raise E('field access digest '+d)

    got=drop.calls(body)
    if got!=[(0x0075,0x28,DAMAGE),(0x00AA,0x28,RATE)]: raise E('call surface '+repr(got))
    dm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,DAMAGE)
    if dm[4]!='GetDamageLevel_LMH' or dm[7]!=('PlayerController_AI','') or len(dm[9])!=49 or hashlib.sha256(dm[9]).hexdigest()!=DAMAGE_SHA: raise E('FACT-0038 identity')
    rm=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,RATE)
    if rm[4]!='mRate100Check' or rm[7]!=('MatchMisc','') or len(rm[9])!=38 or hashlib.sha256(rm[9]).hexdigest()!=RATE_SHA: raise E('FACT-0025 identity')

    for il,op,target in [
        (0x0020,0x3b,0x0037),(0x0032,0x40,0x003e),(0x0039,0x38,0x0063),
        (0x004b,0x40,0x0063),(0x005c,0x3a,0x0063),(0x0064,0x3a,0x006a),
        (0x007e,0x3a,0x008f),(0x008a,0x38,0x00a9),(0x0091,0x40,0x00a2),
        (0x009d,0x38,0x00a9),(0x00af,0x39,0x00c6)
    ]:
        if body[il]!=op or drop.target4(body,il)!=target: raise E('branch '+hex(il))

    if body[0x001e:0x0020]!=bytes([0x1f,17]) or body[0x0030:0x0032]!=bytes([0x1f,18]) or body[0x0049:0x004b]!=bytes([0x1f,22]): raise E('raw State literals')
    if not (body[0x0056]==0x20 and struct.unpack_from('<i',body,0x0057)[0]==752 and body[0x005b]==0x5f): raise E('padPush mask 752')
    if not (body[0x00b4]==0x02 and body[0x00b5]==0x25 and body[0x00b6]==0x7b and body[0x00bb]==0x20 and struct.unpack_from('<i',body,0x00bc)[0]==256 and body[0x00c0]==0x60 and body[0x00c1]==0x7d): raise E('padOn OR 256')
    if body[0x0069]!=0x2a or body[0x00c6]!=0x2a: raise E('return sites')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    expected=[{'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Update','caller_token':'0x0600502B','caller_rva':'0x002FFC68','caller_code_size':984,'caller_code_sha256':PARENT_SHA,'call_il':'0x03D2','opcode':'call'}]
    if rr!=expected: raise E('direct reference surface '+repr(rr))
    rdigest=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rdigest!=REF_DIGEST: raise E('reference digest '+rdigest)
    if hashlib.sha256(('0x0600502B\n').encode()).hexdigest()!=CALLER_DIGEST: raise E('caller digest')

    parent=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,PARENT)
    if parent[1]!=PARENT_RVA or parent[4]!='Update' or parent[7]!=('PlayerController_AI','') or len(parent[9])!=PARENT_SIZE or hashlib.sha256(parent[9]).hexdigest()!=PARENT_SHA: raise E('AI Update identity')
    if parent[9][PARENT_CALL_IL]!=0x28 or struct.unpack_from('<I',parent[9],PARENT_CALL_IL+1)[0]!=T: raise E('AI Update callsite')

    return {'code_size':199,'code_sha256':SHA,'canonical_internal_methoddef_reference_count':2,'external_memberref_count':0,'direct_reference_count':1,'direct_caller_method_count':1,'reference_map_sha256':rdigest}

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={'PlayerController_AI.Process_Uke':0,'PlayerController_AI.GetDamageLevel_LMH':0,'MatchMisc.mRate100Check':0,'PlayerController_AI.Update':0}
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
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_UKE: PASS'); return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_PROCESS_UKE: FAIL'); print(str(e)); return 1

if __name__=='__main__': raise SystemExit(main())
