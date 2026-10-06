#!/usr/bin/env python3
import argparse,csv,hashlib,io,json,struct,zipfile
from pathlib import Path
import prove_playercontroller_ai_process_drop_weapon as drop

base=drop.base
DLL_SHA='9c03b15486322ace5f35f6a56629cf44534e148f044d5f43b3b796d7dd794fb6'
DLL_SIZE=8171008
R6_SHA='93179c3e9a770c62514f1df89390542389b8b2c399027e60ae15e8335dca5d9d'
EVENT_SHA='79b6511800e04ce198209473366c9d486667629d144c82d897fb1168367b12bd'

T=0x06004F9C
RVA=0x002F5F14
ROW='145f2f0000009100b2340a0096cd0200a83a'
SIG='000111a7c80c'
FLAGS=0x0091
HEADER='13300300310000001f000011'
BODY=bytes.fromhex('0228754900060a067e380d00047b3a0d000416984402000000162a067e380d00047b3a0d000417984402000000172a182a')
SHA='b4eb2ae2869d79032fa0ad8a1ed654496300f2fed1cc8736cdb82f037c089329'

LOCAL_SIG_TOKEN=0x1100001F
LOCAL_SIG_ROW='a8590100'
LOCAL_SIG_BLOB='07010c'
ENUM_RID=2546
ENUM_ROW='03010000727900000000000045039e612d50'
PARAM_ROW='000001003caa0100'

FIELDS={
 0x04000D38:('COMLevelDataManager','inst','1600062201007d0a0000','06128638'),
 0x04000D3A:('COMLevelDataManager','damageLevelThreshold_LHF','0600553e0100a7020000','061d0c')
}
ACCESS=[
 (0x0008,'ldsfld',0x04000D38),(0x000D,'ldfld',0x04000D3A),
 (0x001C,'ldsfld',0x04000D38),(0x0021,'ldfld',0x04000D3A)
]
FIELD_DIGEST='ba5bd824c6362063a086eddb054ebfdc3bf47338c261b80157d07b3b02bdd3c4'

CHILD=0x06004975
CHILD_SHA='60de3a243171244b6e09508e9a73f00d82aa76207ad3e8dd046322bc7b849e6c'
CALL_DIGEST='b87deb45729697e188e61d504a1c624647acae90f54c60caa88f0f2593b37d70'
BRANCH_DIGEST='9655d77aabe239d7d5c59d2d4c61dc3ce6e56b3e648112502717e1436045c229'

EXPECTED_REFS=[
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_DownAttack','caller_token':'0x06004FEA','caller_rva':'0x002FA718','caller_code_size':252,'caller_code_sha256':'52ce42d4aae99b7986e46e5efdb1bc462f061e3b235c40346c237942b745a211','call_il':'0x0040','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive','caller_token':'0x06004FED','caller_rva':'0x002FA89C','caller_code_size':366,'caller_code_sha256':'113579d5d828a5604a57b58e74cd969ad4516645249c10fe412a7d5f03a32cac','call_il':'0x007D','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentDown_Dive_Stun','caller_token':'0x06004FEE','caller_rva':'0x002FAA18','caller_code_size':505,'caller_code_sha256':'8d5273fae9c0e6ba9fb560dd8e34d26f3c95488a620abc08c74271f6deb513ec','call_il':'0x008F','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'Process_OpponentStands_Stun','caller_token':'0x06004FF5','caller_rva':'0x002FB600','caller_code_size':529,'caller_code_sha256':'5fbd6ae8165dddc79955e82707aae05da98fb26cfcef5bc9ce69929944189037','call_il':'0x015F','opcode':'call'},
 {'caller_type':'PlayerController_AI','caller_namespace':'','caller_method':'CheckOverTheTopRope','caller_token':'0x0600500F','caller_rva':'0x002FD9D0','caller_code_size':185,'caller_code_sha256':'012aa7bca99f0e1526dccdfcf9a5eda3c63bfb902526b92b66100bf24e6fd93b','call_il':'0x0053','opcode':'call'}
]
REF_DIGEST='55742080af9dbdefe43d7a5664854d641b0c8d7df250f3e1f1307c32b8195403'
CALLER_DIGEST='b0c8a1ab8a339ba9d344c9781a3389709e20acd5fd61bd8d6628b97c3ff63867'

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
    if len(pe)!=DLL_SIZE or hashlib.sha256(pe).hexdigest()!=DLL_SHA: raise E('DLL identity')
    ss,q=base.secs(pe)
    st,hs,rows,tp=base.mdstreams(pe,ss,q)
    s,b,ix,z,o=base.tables(pe,st,hs,rows,tp)
    sb=st['#Strings'][0]; bb=st['#Blob'][0]
    fm,owners=base.owner_maps(pe,rows,s,ix,z,o,sb)

    md=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T)
    raw,rva,impl,flags,name,sig,plist,owner,start,body=md
    if (raw,rva,impl,flags,name,sig,owner)!=(ROW,RVA,0,FLAGS,'GetDamageLevel_LHF',SIG,('PlayerController_AI','')):
        raise E('method metadata')
    nxt=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,T+1)
    if nxt[6]!=plist+1: raise E('parameter range')
    pp=o[8]+(plist-1)*z[8]
    if pe[pp:pp+z[8]].hex()!=PARAM_ROW: raise E('parameter row')
    q2=pp+4
    ni,_=base.rd(pe,q2,s)
    if base.s_at(pe,sb,ni)!='hp': raise E('parameter name')

    ho=base.off(ss,RVA)
    if pe[ho:ho+12].hex()!=HEADER: raise E('fat header')
    if struct.unpack_from('<H',pe,ho+2)[0]!=3 or struct.unpack_from('<I',pe,ho+8)[0]!=LOCAL_SIG_TOKEN:
        raise E('fat header fields')
    if body!=BODY or hashlib.sha256(body).hexdigest()!=SHA: raise E('body')

    sp=o[17]+((LOCAL_SIG_TOKEN&0xffffff)-1)*z[17]
    sraw=pe[sp:sp+z[17]].hex()
    si,_=base.rd(pe,sp,b)
    if sraw!=LOCAL_SIG_ROW or base.blob(pe,bb,si).hex()!=LOCAL_SIG_BLOB: raise E('local signature')
    traw,tname,tns,_,_,_=drop.typedef(pe,rows,s,ix,z,o,sb,ENUM_RID)
    if (traw,tname,tns)!=(ENUM_ROW,'DamageLevelEnum_LHF',''): raise E('return enum TypeDef')

    for tok,(own,nm,row,sg) in FIELDS.items():
        if drop.field(pe,s,b,z,o,sb,bb,fm,tok)!=(row,(own,''),nm,sg): raise E('field '+hex(tok))

    opbytes={'ldsfld':0x7e,'ldfld':0x7b}
    amap=[]
    for il,opname,tok in ACCESS:
        if body[il]!=opbytes[opname] or struct.unpack_from('<I',body,il+1)[0]!=tok:
            raise E('field access '+hex(il))
        amap.append({'il':f'0x{il:04X}','opcode':opname,'token':f'0x{tok:08X}'})
    fd=hashlib.sha256(json.dumps(amap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if fd!=FIELD_DIGEST: raise E('field digest '+fd)

    if drop.calls(body)!=[(0x0001,0x28,CHILD)]: raise E('call surface '+repr(drop.calls(body)))
    ch=drop.method(pe,ss,s,b,ix,z,o,sb,bb,owners,CHILD)
    if ch[4]!='GetParamRate' or ch[7]!=('MatchMisc','') or len(ch[9])!=16 or hashlib.sha256(ch[9]).hexdigest()!=CHILD_SHA:
        raise E('FACT-0031 child identity')
    cmap=[{'il':'0x0001','opcode':'call','token':'0x06004975'}]
    cd=hashlib.sha256(json.dumps(cmap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if cd!=CALL_DIGEST: raise E('call digest '+cd)

    if body[0x0014]!=0x44 or target4(body,0x0014)!=0x001B: raise E('first blt.un')
    if body[0x0028]!=0x44 or target4(body,0x0028)!=0x002F: raise E('second blt.un')
    bmap=[{'il':'0x0014','opcode':'blt.un','target':'0x001B'},
          {'il':'0x0028','opcode':'blt.un','target':'0x002F'}]
    bd=hashlib.sha256(json.dumps(bmap,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if bd!=BRANCH_DIGEST: raise E('branch digest '+bd)
    if body[0x0012:0x0014]!=bytes([0x16,0x98]): raise E('threshold index0')
    if body[0x0019:0x001B]!=bytes([0x16,0x2a]): raise E('raw return0')
    if body[0x0026:0x0028]!=bytes([0x17,0x98]): raise E('threshold index1')
    if body[0x002d:0x0031]!=bytes([0x17,0x2a,0x18,0x2a]): raise E('raw returns1/2')

    rr=refs(pe,ss,s,b,ix,z,o,sb,bb,owners,rows)
    if rr!=EXPECTED_REFS: raise E('reference surface '+repr(rr))
    rd=hashlib.sha256(json.dumps(rr,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if rd!=REF_DIGEST: raise E('reference digest '+rd)
    callers=sorted({x['caller_token'] for x in rr})
    ctd=hashlib.sha256(('\n'.join(callers)+'\n').encode()).hexdigest()
    if ctd!=CALLER_DIGEST: raise E('caller digest '+ctd)

    return {
      'code_size':49,'code_sha256':SHA,'field_access_count':4,
      'methoddef_call_site_count':1,'memberref_method_call_count':0,
      'branch_instruction_count':2,'direct_reference_count':5,'direct_caller_method_count':5,
      'reference_map_sha256':rd
    }

def verify_r6(path):
    if sh(path)!=R6_SHA: raise E('R6 identity')
    wanted={
      'PlayerController_AI.GetDamageLevel_LHF':0,
      'MatchMisc.GetParamRate':0,
      'PlayerController_AI.Process_OpponentDown_DownAttack':0,
      'PlayerController_AI.Process_OpponentDown_Dive':0,
      'PlayerController_AI.Process_OpponentDown_Dive_Stun':0,
      'PlayerController_AI.Process_OpponentStands_Stun':0,
      'PlayerController_AI.CheckOverTheTopRope':0
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
        print('PROVE_PLAYERCONTROLLER_AI_GET_DAMAGE_LEVEL_LHF: PASS')
        return 0
    except Exception as e:
        print('PROVE_PLAYERCONTROLLER_AI_GET_DAMAGE_LEVEL_LHF: FAIL')
        print(str(e))
        return 1

if __name__=='__main__': raise SystemExit(main())
